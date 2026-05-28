// Package moonraker implements a non-blocking WebSocket client for the
// Moonraker JSON-RPC API. It identifies as an "agent" to Moonraker,
// subscribes to the minimal telemetry set, and emits printer state deltas
// on a channel without blocking Klipper's motion path.
package moonraker

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
)

const (
	jsonrpcVersion = "2.0"

	writeTimeout = 10 * time.Second
	readTimeout  = 90 * time.Second // Moonraker sends pings; silence > 90s is a problem.
	pingInterval = 30 * time.Second
)

// StatusDelta is sent on the Updates channel whenever Moonraker emits a
// notify_status_update notification. The Status map contains only the changed
// fields from that notification cycle.
type StatusDelta struct {
	Status     map[string]json.RawMessage
	EventTime  float64
	ReceivedAt time.Time
}

// Client is a long-lived Moonraker WebSocket connection that auto-reconnects.
type Client struct {
	endpoint    string
	apiKey      string
	clientName  string
	clientVer   string
	reconnDelay time.Duration
	subObjects  map[string]interface{}

	// Updates is the outbound channel. The custody packetizer reads from this.
	// It is buffered so a slow consumer does not stall the WS reader goroutine.
	Updates chan StatusDelta

	log    *slog.Logger
	nextID atomic.Int64

	mu   sync.Mutex
	conn *websocket.Conn

	// pending maps request IDs to response channels for synchronous RPC calls.
	pendingMu sync.Mutex
	pending   map[int64]chan Response
}

// NewClient creates a client but does not connect. Call Run to start.
func NewClient(
	endpoint, apiKey, clientName, clientVer string,
	reconnDelay time.Duration,
	subObjects map[string]interface{},
	log *slog.Logger,
) *Client {
	if subObjects == nil {
		subObjects = DefaultSubscribeObjects()
	}
	return &Client{
		endpoint:    endpoint,
		apiKey:      apiKey,
		clientName:  clientName,
		clientVer:   clientVer,
		reconnDelay: reconnDelay,
		subObjects:  subObjects,
		Updates:     make(chan StatusDelta, 64),
		log:         log,
		pending:     make(map[int64]chan Response),
	}
}

// Run connects to Moonraker, identifies as an agent, subscribes to printer
// objects, and pumps incoming notifications to Updates. It reconnects on
// disconnect until ctx is cancelled.
func (c *Client) Run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		if err := c.runOnce(ctx); err != nil {
			c.log.Warn("moonraker: connection ended, will retry",
				"error", err,
				"delay", c.reconnDelay)
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(c.reconnDelay):
		}
	}
}

func (c *Client) runOnce(ctx context.Context) error {
	dialer := websocket.Dialer{HandshakeTimeout: 10 * time.Second}
	hdr := make(map[string][]string)
	if c.apiKey != "" {
		hdr["X-Api-Key"] = []string{c.apiKey}
	}

	conn, _, err := dialer.DialContext(ctx, c.endpoint, hdr)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()

	c.mu.Lock()
	c.conn = conn
	c.mu.Unlock()

	c.log.Info("moonraker: connected", "endpoint", c.endpoint)

	// Goroutine for ping/keepalive.
	pingCtx, cancelPing := context.WithCancel(ctx)
	defer cancelPing()
	go c.pingLoop(pingCtx, conn)

	// Identify as agent.
	if err := c.identify(conn); err != nil {
		return fmt.Errorf("identify: %w", err)
	}

	// Wait for Moonraker to confirm Klipper is ready.
	if err := c.waitReady(ctx, conn); err != nil {
		return fmt.Errorf("wait ready: %w", err)
	}

	// Subscribe to printer objects.
	if err := c.subscribe(conn); err != nil {
		return fmt.Errorf("subscribe: %w", err)
	}

	// Pump messages.
	return c.readLoop(ctx, conn)
}

func (c *Client) nextRequestID() int64 {
	return c.nextID.Add(1)
}

func (c *Client) send(conn *websocket.Conn, method string, params interface{}) (int64, error) {
	id := c.nextRequestID()
	p, err := json.Marshal(params)
	if err != nil {
		return 0, err
	}
	req := Request{
		JSONRPC: jsonrpcVersion,
		ID:      int(id),
		Method:  method,
		Params:  p,
	}
	conn.SetWriteDeadline(time.Now().Add(writeTimeout))
	if err := conn.WriteJSON(req); err != nil {
		return 0, fmt.Errorf("write %s: %w", method, err)
	}
	return id, nil
}

// call sends a request and synchronously waits for the matching response.
func (c *Client) call(ctx context.Context, conn *websocket.Conn, method string, params interface{}) (json.RawMessage, error) {
	ch := make(chan Response, 1)
	id, err := c.send(conn, method, params)
	if err != nil {
		return nil, err
	}

	c.pendingMu.Lock()
	c.pending[id] = ch
	c.pendingMu.Unlock()

	defer func() {
		c.pendingMu.Lock()
		delete(c.pending, id)
		c.pendingMu.Unlock()
	}()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case resp := <-ch:
		if resp.Error != nil {
			return nil, fmt.Errorf("rpc error %d: %s", resp.Error.Code, resp.Error.Message)
		}
		return resp.Result, nil
	case <-time.After(15 * time.Second):
		return nil, fmt.Errorf("timeout waiting for response to %s", method)
	}
}

func (c *Client) identify(conn *websocket.Conn) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	params := IdentifyParams{
		ClientName: c.clientName,
		Version:    c.clientVer,
		Type:       "agent",
		URL:        "internal",
	}
	result, err := c.call(ctx, conn, "server.connection.identify", params)
	if err != nil {
		return err
	}
	c.log.Info("moonraker: identified", "result", string(result))
	return nil
}

func (c *Client) waitReady(ctx context.Context, conn *websocket.Conn) error {
	// Poll server.info until klippy is ready or ctx expires.
	for {
		result, err := c.call(ctx, conn, "server.info", nil)
		if err != nil {
			return err
		}
		var info struct {
			KlippyState string `json:"klippy_state"`
		}
		if err := json.Unmarshal(result, &info); err != nil {
			return err
		}
		if info.KlippyState == "ready" {
			c.log.Info("moonraker: klippy ready")
			return nil
		}
		c.log.Info("moonraker: klippy not ready, waiting", "state", info.KlippyState)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(3 * time.Second):
		}
	}
}

func (c *Client) subscribe(conn *websocket.Conn) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	params := SubscribeParams{Objects: c.subObjects}
	result, err := c.call(ctx, conn, "printer.objects.subscribe", params)
	if err != nil {
		return err
	}

	// The response includes the initial full state snapshot.
	var snap struct {
		Status    map[string]json.RawMessage `json:"status"`
		EventTime float64                    `json:"eventtime"`
	}
	if err := json.Unmarshal(result, &snap); err != nil {
		return fmt.Errorf("decode initial snapshot: %w", err)
	}
	if len(snap.Status) > 0 {
		c.Updates <- StatusDelta{
			Status:     snap.Status,
			EventTime:  snap.EventTime,
			ReceivedAt: time.Now(),
		}
	}
	c.log.Info("moonraker: subscribed to printer objects", "count", len(c.subObjects))
	return nil
}

func (c *Client) readLoop(ctx context.Context, conn *websocket.Conn) error {
	for {
		conn.SetReadDeadline(time.Now().Add(readTimeout))
		_, data, err := conn.ReadMessage()
		if err != nil {
			return fmt.Errorf("read: %w", err)
		}

		var resp Response
		if err := json.Unmarshal(data, &resp); err != nil {
			c.log.Warn("moonraker: could not decode message", "error", err)
			continue
		}

		// Route to pending synchronous calls.
		if resp.ID != 0 {
			c.pendingMu.Lock()
			ch, ok := c.pending[int64(resp.ID)]
			c.pendingMu.Unlock()
			if ok {
				select {
				case ch <- resp:
				default:
				}
			}
			continue
		}

		// Handle notifications.
		switch resp.Method {
		case "notify_status_update":
			c.handleStatusUpdate(resp.Params)
		case "notify_klippy_disconnected":
			c.log.Warn("moonraker: klippy disconnected")
			return fmt.Errorf("klippy disconnected")
		case "notify_klippy_ready":
			c.log.Info("moonraker: klippy ready (notification)")
		}
	}
}

func (c *Client) handleStatusUpdate(raw json.RawMessage) {
	// notify_status_update params is an array: [status_map, eventtime]
	var params []json.RawMessage
	if err := json.Unmarshal(raw, &params); err != nil || len(params) < 2 {
		c.log.Warn("moonraker: malformed status update", "raw", string(raw))
		return
	}

	var status map[string]json.RawMessage
	var eventTime float64
	if err := json.Unmarshal(params[0], &status); err != nil {
		return
	}
	json.Unmarshal(params[1], &eventTime)

	select {
	case c.Updates <- StatusDelta{
		Status:     status,
		EventTime:  eventTime,
		ReceivedAt: time.Now(),
	}:
	default:
		// Drop if consumer is not keeping up. The custody packetizer will
		// see the stale state and produce a continuity packet regardless.
		c.log.Warn("moonraker: updates channel full, delta dropped")
	}
}

func (c *Client) pingLoop(ctx context.Context, conn *websocket.Conn) {
	ticker := time.NewTicker(pingInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			conn.SetWriteDeadline(time.Now().Add(writeTimeout))
			if err := conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}
