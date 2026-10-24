package fleet

import (
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// The link is each agent's persistent mTLS WebSocket, used as a doorbell and for presence. When a
// command is queued the panel rings ({"t":"commands"}) and the agent fetches it right away over
// GET /commands — the same allowlisted, acked path as before; no command data rides the link.
// Whether the link is up is the machine's online state, known the moment it changes. Commands are
// only accepted for an online machine.

const (
	linkPingEvery = 10 * time.Second
	linkReadWait  = 25 * time.Second // no pong this long = dead link (a machine that just vanished)
	// linkGrace: a link that drops and comes back within this (panel or network blip) still
	// counts as up, so the UI doesn't flicker offline. An agent that says it's going away
	// (reboot, agent stopping) skips it.
	linkGrace = 20 * time.Second
)

type agentLink struct {
	conn *websocket.Conn
	wmu  sync.Mutex // serializes data-frame writes (pings use WriteControl, which is safe)
}

func (l *agentLink) ring() {
	l.wmu.Lock()
	defer l.wmu.Unlock()
	_ = l.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_ = l.conn.WriteJSON(map[string]string{"t": "commands"})
}

var links = struct {
	sync.Mutex
	up   map[string]*agentLink
	down map[string]time.Time // when a link dropped (only machines that had one since start)
}{up: map[string]*agentLink{}, down: map[string]time.Time{}}

// linkOnline reports whether a machine's link is up (or dropped less than linkGrace ago).
func linkOnline(machineID string) bool {
	links.Lock()
	defer links.Unlock()
	if links.up[machineID] != nil {
		return true
	}
	t, ok := links.down[machineID]
	return ok && time.Since(t) < linkGrace
}

// ringLink tells a connected agent that commands are waiting. No-op without a link: the agent
// then finds them on its next poll.
func ringLink(machineID string) {
	links.Lock()
	l := links.up[machineID]
	links.Unlock()
	if l != nil {
		go l.ring() // never hold up the request that queued the command
	}
}

// linkTeardown drops a machine's link and forgets its state (revoked or deleted machine).
func linkTeardown(machineID string) {
	links.Lock()
	l := links.up[machineID]
	delete(links.up, machineID)
	delete(links.down, machineID)
	links.Unlock()
	if l != nil {
		l.conn.Close()
	}
}

// HandleLink upgrades an agent's link (client-cert authed via requireClientCert) and holds it
// until it drops, pinging to detect a dead peer.
func (s *Service) HandleLink(w http.ResponseWriter, r *http.Request) {
	m := machineFrom(r)
	if m == nil {
		writeErr(w, http.StatusUnauthorized, "no machine")
		return
	}
	conn, err := agentUpgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	conn.SetReadLimit(4 << 10) // the agent sends nothing but pongs
	l := &agentLink{conn: conn}

	links.Lock()
	old := links.up[m.ID]
	links.up[m.ID] = l
	delete(links.down, m.ID)
	links.Unlock()
	if old != nil {
		old.conn.Close() // a reconnect replaces the stale link
	}
	s.broadcastLink(m.ID, true)

	stop := keepAlive(conn)
	var readErr error
	for {
		if _, _, readErr = conn.NextReader(); readErr != nil {
			break
		}
	}
	stop()
	conn.Close()
	goingAway := websocket.IsCloseError(readErr, websocket.CloseGoingAway)

	links.Lock()
	current := links.up[m.ID] == l
	if current {
		delete(links.up, m.ID)
		links.down[m.ID] = time.Now()
		if goingAway { // the agent said it's leaving: offline now, no grace
			links.down[m.ID] = time.Now().Add(-linkGrace)
		}
	}
	links.Unlock()
	if current && goingAway {
		s.broadcastLink(m.ID, false)
	} else if current {
		// Tell watchers only if it stays down past the grace period.
		time.AfterFunc(linkGrace, func() {
			if !linkOnline(m.ID) {
				s.broadcastLink(m.ID, false)
			}
		})
	}
}

// broadcastLink pushes a presence change to browsers allowed to see the machine.
func (s *Service) broadcastLink(machineID string, online bool) {
	s.scopedBroadcast(machineID, "fleet", map[string]any{"machine_id": machineID, "online": online})
}

// keepAlive pings an agent connection every linkPingEvery; with no pong for linkReadWait the peer
// is gone (a machine that vanished without closing), and the connection's next read fails. Agents
// answer pings by themselves. stop ends the pinging, once the reader is done.
func keepAlive(conn *websocket.Conn) (stop func()) {
	done := make(chan struct{})
	go func() {
		t := time.NewTicker(linkPingEvery)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-t.C:
				if conn.WriteControl(websocket.PingMessage, nil, time.Now().Add(5*time.Second)) != nil {
					conn.Close()
					return
				}
			}
		}
	}()
	_ = conn.SetReadDeadline(time.Now().Add(linkReadWait))
	conn.SetPongHandler(func(string) error { return conn.SetReadDeadline(time.Now().Add(linkReadWait)) })
	return func() { close(done) }
}
