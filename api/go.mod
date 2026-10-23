module api

go 1.26.0

// Patched Go for every build (local, tests, CI); matches the Dockerfile. The standard library
// is compiled in, so an unpatched toolchain ships its CVEs.
toolchain go1.26.10

require (
	github.com/SherClockHolmes/webpush-go v1.4.0
	github.com/go-webauthn/webauthn v0.18.2
	github.com/gorilla/websocket v1.5.3
	github.com/ip2location/ip2location-go/v9 v9.8.0
	github.com/mattn/go-sqlite3 v1.14.52
	github.com/minio/minio-go/v7 v7.4.1
	github.com/oschwald/maxminddb-golang v1.13.1
	github.com/pkg/sftp v1.13.11
	github.com/pquerna/otp v1.5.0
	github.com/skip2/go-qrcode v0.0.0-20200617195104-da1b6568686e
	golang.org/x/crypto v0.58.0
	golang.zx2c4.com/wireguard/wgctrl v0.0.0-20241231184526-a9ab2273dd10
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/boombuler/barcode v1.0.1-0.20190219062509-6c824513bacc // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/fxamacker/cbor/v2 v2.9.4 // indirect
	github.com/go-viper/mapstructure/v2 v2.5.0 // indirect
	github.com/go-webauthn/x v0.3.1 // indirect
	github.com/golang-jwt/jwt/v5 v5.3.1 // indirect
	github.com/google/go-tpm v0.9.8 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/klauspost/compress v1.19.2 // indirect
	github.com/klauspost/cpuid/v2 v2.4.0 // indirect
	github.com/klauspost/crc32 v1.3.0 // indirect
	github.com/kr/fs v0.1.0 // indirect
	github.com/minio/crc64nvme v1.1.1 // indirect
	github.com/minio/md5-simd v1.1.2 // indirect
	github.com/philhofer/fwd v1.2.0 // indirect
	github.com/rs/xid v1.6.0 // indirect
	github.com/tinylib/msgp v1.6.4 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	github.com/zeebo/xxh3 v1.1.0 // indirect
	go.yaml.in/yaml/v3 v3.0.5 // indirect
	golang.org/x/net v0.60.0 // indirect
	golang.org/x/sys v0.49.0 // indirect
	golang.org/x/text v0.43.0 // indirect
	gopkg.in/ini.v1 v1.67.3 // indirect
	lukechampine.com/uint128 v1.2.0 // indirect
)
