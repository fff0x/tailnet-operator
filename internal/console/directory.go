package console

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"tsunaro.io/tailnet-operator/internal/headscale"
)

// ponytail: every answer, an error too, is kept for directoryTTL, so a page shows a grant, a user
// or a node change up to 15 s late, and the operator sees at most three calls per Tailnet in that
// time. One lock serialises the reads, so a slow Tailnet delays the others, and the page, by up to
// loadTimeout. A watch would remove the delay; a lock per Tailnet would remove the blocking.
const directoryTTL = 15 * time.Second

// loadTimeout bounds the three reads of one Tailnet together. The overview waits for every Tailnet
// in turn, so an operator that drops the packets must cost far less than the server's write timeout.
const loadTimeout = 3 * time.Second

// tailnetData is what the operator's console API returns for one Tailnet. Users are personal data:
// they stay in memory for directoryTTL and never reach a log.
type tailnetData struct {
	Users  []headscale.User
	Nodes  []taggedNode
	Policy string
}

// taggedNode keeps what the map needs; the node's name is not even decoded.
type taggedNode struct {
	Online bool     `json:"online"`
	Tags   []string `json:"tags"`
}

// directory reads Headscale users, tagged nodes and the live policy from the operator. The
// projected token is read on every call, because the kubelet rotates the file.
type directory struct {
	base      string
	tokenFile string
	client    *http.Client
	now       func() time.Time
	timeout   time.Duration
	fetch     sync.Mutex // held while reading the operator
	mu        sync.Mutex // guards cache
	cache     map[string]cachedData
}

type cachedData struct {
	at   time.Time
	data tailnetData
	err  error
}

func newDirectory(base, tokenFile string) *directory {
	return &directory{base: strings.TrimSuffix(base, "/"), tokenFile: tokenFile, client: &http.Client{Timeout: 10 * time.Second},
		now: time.Now, timeout: loadTimeout, cache: map[string]cachedData{}}
}

func (d *directory) cached(tailnet string) (cachedData, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	c, ok := d.cache[tailnet]
	return c, ok && d.now().Sub(c.at) < directoryTTL
}

func (d *directory) get(ctx context.Context, tailnet string) (tailnetData, error) {
	if c, ok := d.cached(tailnet); ok {
		return c.data, c.err
	}
	d.fetch.Lock()
	defer d.fetch.Unlock()
	if c, ok := d.cached(tailnet); ok {
		return c.data, c.err
	}
	bounded, cancel := context.WithTimeout(ctx, d.timeout)
	data, err := d.load(bounded, tailnet)
	cancel()
	if ctx.Err() != nil {
		return data, err // the caller left; the operator's answer is unknown
	}
	d.mu.Lock()
	d.cache[tailnet] = cachedData{at: d.now(), data: data, err: err}
	d.mu.Unlock()
	return data, err
}

func (d *directory) load(ctx context.Context, tailnet string) (tailnetData, error) {
	var users struct {
		Users []headscale.User `json:"users"`
	}
	var nodes struct {
		Nodes []taggedNode `json:"nodes"`
	}
	var policy struct {
		Policy string `json:"policy"`
	}
	if err := d.read(ctx, tailnet, "users", &users); err != nil {
		return tailnetData{}, err
	}
	if err := d.read(ctx, tailnet, "nodes", &nodes); err != nil {
		return tailnetData{}, err
	}
	if err := d.read(ctx, tailnet, "policy", &policy); err != nil {
		return tailnetData{}, err
	}
	return tailnetData{Users: users.Users, Nodes: nodes.Nodes, Policy: policy.Policy}, nil
}

// read never returns response text: the error names the path and the status only.
func (d *directory) read(ctx context.Context, tailnet, kind string, out any) error {
	token, err := os.ReadFile(d.tokenFile)
	if err != nil {
		return fmt.Errorf("console API token unreadable")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, d.base+"/v1/tailnets/"+url.PathEscape(tailnet)+"/"+kind, nil)
	if err != nil {
		return fmt.Errorf("console API request invalid")
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(token)))
	resp, err := d.client.Do(req)
	if err != nil {
		return fmt.Errorf("console API %s unreachable", kind)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("console API %s: HTTP %d", kind, resp.StatusCode)
	}
	if json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(out) != nil {
		return fmt.Errorf("console API %s: invalid answer", kind)
	}
	return nil
}
