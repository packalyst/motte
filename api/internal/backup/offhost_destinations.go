package backup

import (
	"context"
	"crypto/subtle"
	"fmt"
	"net"
	"os"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

// remoteObject is one archive already stored at a destination.
type remoteObject struct {
	Name    string    `json:"name"`
	Size    int64     `json:"size"`
	ModTime time.Time `json:"modTime"`
}

// backend abstracts an off-host target. learnedHostKey returns a newly-observed SSH host key to
// pin (SFTP TOFU); "" for backends that don't apply.
type backend interface {
	put(ctx context.Context, localPath, name string) error
	get(ctx context.Context, name, localPath string) error
	list(ctx context.Context) ([]remoteObject, error)
	remove(ctx context.Context, name string) error
	learnedHostKey() string
	close() error
}

func newBackend(d Destination) (backend, error) {
	switch d.Type {
	case "s3":
		return newS3Backend(d)
	case "sftp":
		return newSFTPBackend(d)
	default:
		return nil, fmt.Errorf("unknown destination type %q", d.Type)
	}
}

// archiveName reports whether an object name is one of our archives (so listing/pruning never
// touches unrelated files sharing the bucket/dir).
func isArchiveName(name string) bool {
	return strings.HasPrefix(path.Base(name), "motte-") && strings.HasSuffix(name, ".wgbackup")
}

// ---- S3-compatible (minio-go) ----

type s3Backend struct {
	cl     *minio.Client
	bucket string
	prefix string
}

func newS3Backend(d Destination) (backend, error) {
	cl, err := minio.New(d.Endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(d.AccessKey, d.SecretKey, ""),
		Secure: d.UseSSL,
		Region: d.Region,
	})
	if err != nil {
		return nil, err
	}
	return &s3Backend{cl: cl, bucket: d.Bucket, prefix: strings.Trim(d.Prefix, "/")}, nil
}

func (b *s3Backend) key(name string) string {
	if b.prefix == "" {
		return name
	}
	return b.prefix + "/" + name
}

func (b *s3Backend) put(ctx context.Context, localPath, name string) error {
	f, err := os.Open(localPath)
	if err != nil {
		return err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	_, err = b.cl.PutObject(ctx, b.bucket, b.key(name), f, fi.Size(), minio.PutObjectOptions{
		ContentType: "application/octet-stream",
	})
	return err
}

func (b *s3Backend) get(ctx context.Context, name, localPath string) error {
	return b.cl.FGetObject(ctx, b.bucket, b.key(name), localPath, minio.GetObjectOptions{})
}

func (b *s3Backend) list(ctx context.Context) ([]remoteObject, error) {
	var out []remoteObject
	prefix := b.prefix
	if prefix != "" {
		prefix += "/"
	}
	for obj := range b.cl.ListObjects(ctx, b.bucket, minio.ListObjectsOptions{Prefix: prefix, Recursive: true}) {
		if obj.Err != nil {
			return nil, obj.Err
		}
		if !isArchiveName(obj.Key) {
			continue
		}
		out = append(out, remoteObject{Name: path.Base(obj.Key), Size: obj.Size, ModTime: obj.LastModified})
	}
	return out, nil
}

func (b *s3Backend) remove(ctx context.Context, name string) error {
	return b.cl.RemoveObject(ctx, b.bucket, b.key(name), minio.RemoveObjectOptions{})
}

func (b *s3Backend) learnedHostKey() string { return "" }
func (b *s3Backend) close() error           { return nil }

// ---- SFTP (pkg/sftp over x/crypto/ssh) ----

type sftpBackend struct {
	ssh  *ssh.Client
	cl   *sftp.Client
	dir  string
	seen string // host key observed this session (for TOFU pinning)
}

func newSFTPBackend(d Destination) (backend, error) {
	port := d.Port
	if port == 0 {
		port = 22
	}
	var auth []ssh.AuthMethod
	if d.PrivateKey != "" {
		signer, err := ssh.ParsePrivateKey([]byte(d.PrivateKey))
		if err != nil {
			return nil, fmt.Errorf("invalid SFTP private key: %w", err)
		}
		auth = append(auth, ssh.PublicKeys(signer))
	}
	if d.Password != "" {
		auth = append(auth, ssh.Password(d.Password))
	}
	if len(auth) == 0 {
		return nil, fmt.Errorf("SFTP needs a password or private key")
	}

	b := &sftpBackend{dir: d.Path}
	expected := strings.TrimSpace(d.HostKey)
	cfg := &ssh.ClientConfig{
		User:    d.User,
		Auth:    auth,
		Timeout: 20 * time.Second,
		// Verify the server's host key: strict against a pinned key, else TOFU-record it so the
		// caller can pin it. Never blindly accept an unverified key on an already-pinned host.
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			got := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
			if expected != "" {
				if subtle.ConstantTimeCompare([]byte(got), []byte(expected)) != 1 {
					return fmt.Errorf("SSH host key mismatch (possible MITM) — pinned key does not match the server")
				}
				return nil
			}
			b.seen = got // first contact: record for pinning
			return nil
		},
	}

	conn, err := ssh.Dial("tcp", net.JoinHostPort(d.Host, fmt.Sprintf("%d", port)), cfg)
	if err != nil {
		return nil, err
	}
	cl, err := sftp.NewClient(conn)
	if err != nil {
		conn.Close()
		return nil, err
	}
	b.ssh = conn
	b.cl = cl
	return b, nil
}

func (b *sftpBackend) full(name string) string {
	if b.dir == "" {
		return name
	}
	return path.Join(b.dir, name)
}

func (b *sftpBackend) put(ctx context.Context, localPath, name string) error {
	if b.dir != "" {
		b.cl.MkdirAll(b.dir) // best effort
	}
	src, err := os.Open(localPath)
	if err != nil {
		return err
	}
	defer src.Close()
	dst, err := b.cl.Create(b.full(name))
	if err != nil {
		return err
	}
	if _, err := dst.ReadFrom(src); err != nil {
		dst.Close()
		return err
	}
	return dst.Close()
}

func (b *sftpBackend) get(_ context.Context, name, localPath string) error {
	src, err := b.cl.Open(b.full(name))
	if err != nil {
		return err
	}
	defer src.Close()
	dst, err := os.Create(localPath)
	if err != nil {
		return err
	}
	if _, err := src.WriteTo(dst); err != nil {
		dst.Close()
		return err
	}
	return dst.Close()
}

func (b *sftpBackend) list(_ context.Context) ([]remoteObject, error) {
	dir := b.dir
	if dir == "" {
		dir = "."
	}
	entries, err := b.cl.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []remoteObject
	for _, e := range entries {
		if e.IsDir() || !isArchiveName(e.Name()) {
			continue
		}
		out = append(out, remoteObject{Name: e.Name(), Size: e.Size(), ModTime: e.ModTime()})
	}
	return out, nil
}

func (b *sftpBackend) remove(_ context.Context, name string) error {
	return b.cl.Remove(b.full(name))
}

func (b *sftpBackend) learnedHostKey() string { return b.seen }

func (b *sftpBackend) close() error {
	if b.cl != nil {
		b.cl.Close()
	}
	if b.ssh != nil {
		return b.ssh.Close()
	}
	return nil
}

// pruneKeepN deletes all but the newest keepN archives at the destination. keepN<=0 keeps all.
func pruneKeepN(ctx context.Context, b backend, keepN int) error {
	if keepN <= 0 {
		return nil
	}
	objs, err := b.list(ctx)
	if err != nil {
		return err
	}
	if len(objs) <= keepN {
		return nil
	}
	sort.Slice(objs, func(i, j int) bool { return objs[i].ModTime.After(objs[j].ModTime) })
	for _, o := range objs[keepN:] {
		if err := b.remove(ctx, o.Name); err != nil {
			return err
		}
	}
	return nil
}
