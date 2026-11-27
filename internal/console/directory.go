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

// ponytail: every answer is kept for directoryTTL, so a page shows a grant or a user change up to
// 15 s late and the operator sees at most two calls per Tailnet in that time. A watch would remove
// the delay.
const directoryTTL = 15 * time.Second

// tailnetData is what the operator's console API returns for one Tailnet. Users are personal data:
// they stay in memory for directoryTTL and never reach a log.
type tailnetData struct {
	Users  []headscale.User
	Policy string
}

// directory reads Headscale users and the live policy from the operator. The projected token is
// read on every call, because the kubelet rotates the file.
type directory struct {
	base      string
	tokenFile string
	client    *http.Client
	now       func() time.Time
	mu        sync.Mutex
	cache     map[string]cachedData
}

type cachedData struct {
	at   time.Time
	data tailnetData
}

func newDirectory(base, tokenFile string) *directory {
	return &directory{base: strings.TrimSuffix(base, "/"), tokenFile: tokenFile, client: &http.Client{Timeout: 10 * time.Second},
		now: time.Now, cache: map[string]cachedData{}}
}

func (d *directory) get(ctx context.Context, tailnet string) (tailnetData, error) {
	d.mu.Lock()
	c, ok := d.cache[tailnet]
	d.mu.Unlock()
	if ok && d.now().Sub(c.at) < directoryTTL {
		return c.data, nil
	}
	var users struct {
		Users []headscale.User `json:"users"`
	}
	var policy struct {
		Policy string `json:"policy"`
	}
	if err := d.read(ctx, tailnet, "users", &users); err != nil {
		return tailnetData{}, err
	}
	if err := d.read(ctx, tailnet, "policy", &policy); err != nil {
		return tailnetData{}, err
	}
	data := tailnetData{Users: users.Users, Policy: policy.Policy}
	d.mu.Lock()
	d.cache[tailnet] = cachedData{at: d.now(), data: data}
	d.mu.Unlock()
	return data, nil
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
