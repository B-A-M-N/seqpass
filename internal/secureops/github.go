package secureops

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

func init() {
	Register(&githubGetRepo{})
	Register(&githubListIssues{})
}

// repoRe is the documented GitHub identifier grammar: exactly owner/name,
// ASCII word characters, dots and dashes only. No extra segments, query,
// fragment, encoding tricks or unicode.
var repoRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}/[A-Za-z0-9_.-]{1,100}$`)

func parseRepo(raw string) (owner, name string, err error) {
	if !repoRe.MatchString(raw) {
		return "", "", errors.New("invalid repo: want owner/name")
	}
	parts := strings.SplitN(raw, "/", 2)
	if strings.Contains(parts[0], "..") || strings.Contains(parts[1], "..") {
		return "", "", errors.New("invalid repo: want owner/name")
	}
	return parts[0], parts[1], nil
}

type githubGetRepo struct{}

func (g *githubGetRepo) Name() string               { return "github.get_repo" }
func (g *githubGetRepo) Completion() CompletionMode { return ResponseValidated }
func (g *githubGetRepo) RequiresDestination() bool  { return false }
func (g *githubGetRepo) Describe() DriverInfo {
	return DriverInfo{
		Description:  "Read GitHub repository metadata (name, description, visibility, default branch, open issue count)",
		Params:       []ParamInfo{{Name: "repo", Description: "Repository as owner/name"}},
		ResourceKind: "github.repository",
		Completion:   ResponseValidated,
	}
}
func (g *githubGetRepo) AllowedParams() []string { return []string{"repo"} }

func (g *githubGetRepo) Resource(params map[string]string) ResourceDescriptor {
	owner, name, err := parseRepo(params["repo"])
	if err != nil {
		return ResourceDescriptor{Kind: "github.repository", Identifier: "invalid"}
	}
	return ResourceDescriptor{Kind: "github.repository", Identifier: owner + "/" + name}
}

func (g *githubGetRepo) Validate(in UseInput) error {
	if _, _, err := parseRepo(in.Params["repo"]); err != nil {
		return err
	}
	return nil
}

// githubAPIBase is overridable in tests (httptest server). Production is
// always https://api.github.com; http bases are rejected by githubGET.
var githubAPIBase = "https://api.github.com"

func (g *githubGetRepo) Execute(ctx context.Context, cred Credential, in UseInput) (SafeResult, error) {
	if cred.Value == "" {
		return SafeResult{}, errors.New("no credential")
	}
	owner, name, err := parseRepo(in.Params["repo"])
	if err != nil {
		return SafeResult{}, err
	}
	// URL built from validated components, never raw concatenation.
	url := githubAPIBase + "/repos/" + owner + "/" + name
	return githubGET(ctx, cred.Value, url, "repo")
}

type githubListIssues struct{}

func (g *githubListIssues) Name() string               { return "github.list_issues" }
func (g *githubListIssues) Completion() CompletionMode { return ResponseValidated }
func (g *githubListIssues) RequiresDestination() bool  { return false }
func (g *githubListIssues) Describe() DriverInfo {
	return DriverInfo{
		Description:  "List open GitHub issues (number, title, state, up to 20)",
		Params:       []ParamInfo{{Name: "repo", Description: "Repository as owner/name"}},
		ResourceKind: "github.repository",
		Completion:   ResponseValidated,
	}
}
func (g *githubListIssues) AllowedParams() []string { return []string{"repo"} }

func (g *githubListIssues) Resource(params map[string]string) ResourceDescriptor {
	owner, name, err := parseRepo(params["repo"])
	if err != nil {
		return ResourceDescriptor{Kind: "github.repository", Identifier: "invalid"}
	}
	return ResourceDescriptor{Kind: "github.repository", Identifier: owner + "/" + name}
}

func (g *githubListIssues) Validate(in UseInput) error {
	if _, _, err := parseRepo(in.Params["repo"]); err != nil {
		return err
	}
	return nil
}

func (g *githubListIssues) Execute(ctx context.Context, cred Credential, in UseInput) (SafeResult, error) {
	if cred.Value == "" {
		return SafeResult{}, errors.New("no credential")
	}
	owner, name, err := parseRepo(in.Params["repo"])
	if err != nil {
		return SafeResult{}, err
	}
	url := githubAPIBase + "/repos/" + owner + "/" + name + "/issues?state=open&per_page=20"
	return githubGET(ctx, cred.Value, url, "issues")
}

// repoDTO / issueDTO are the only shapes returned to the agent. Remote text
// is untrusted data: bounded strings, no nested passthrough, no instruction
// interpretation.
type repoDTO struct {
	FullName        string `json:"full_name"`
	Description     string `json:"description"`
	Private         bool   `json:"private"`
	DefaultBranch   string `json:"default_branch"`
	OpenIssuesCount int    `json:"open_issues_count"`
}

type issueDTO struct {
	Number int    `json:"number"`
	Title  string `json:"title"`
	State  string `json:"state"`
}

func strField(m map[string]interface{}, k string, max int) string {
	s, _ := m[k].(string)
	if len(s) > max {
		s = s[:max]
	}
	return s
}

func githubGET(ctx context.Context, token, url, kind string) (SafeResult, error) {
	// URL must stay under the configured API base; production base is https.
	if !strings.HasPrefix(url, githubAPIBase+"/repos/") {
		return SafeResult{}, fmt.Errorf("operation not allowlisted")
	}
	if !strings.HasPrefix(url, "https://") && !strings.HasPrefix(url, "http://127.0.0.1") && !strings.HasPrefix(url, "http://localhost") {
		return SafeResult{}, fmt.Errorf("operation not allowlisted")
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return SafeResult{}, errors.New("request build failed")
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Authorization", "Bearer "+token)
	// Redirects disabled: a credentialed GET must never follow the remote
	// server to another endpoint.
	client := &http.Client{
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return errors.New("redirects disabled for credentialed operations")
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		// Never surface request/transport diagnostics that could carry
		// credential-bearing headers or URLs.
		return SafeResult{}, errors.New("upstream request failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return SafeResult{}, fmt.Errorf("github request failed with status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	if err != nil {
		return SafeResult{}, errors.New("invalid response")
	}
	if kind == "issues" {
		var list []map[string]interface{}
		if err := json.Unmarshal(body, &list); err != nil {
			return SafeResult{}, errors.New("invalid response")
		}
		if len(list) > 20 {
			list = list[:20]
		}
		issues := make([]issueDTO, 0, len(list))
		for _, m := range list {
			n, _ := m["number"].(float64)
			issues = append(issues, issueDTO{
				Number: int(n),
				Title:  strField(m, "title", 300),
				State:  strField(m, "state", 20),
			})
		}
		return SafeResult{Summary: "github ok", Data: map[string]interface{}{"issues": issues}}, nil
	}
	var m map[string]interface{}
	if err := json.Unmarshal(body, &m); err != nil {
		return SafeResult{}, errors.New("invalid response")
	}
	priv, _ := m["private"].(bool)
	n, _ := m["open_issues_count"].(float64)
	repo := repoDTO{
		FullName:        strField(m, "full_name", 200),
		Description:     strField(m, "description", 500),
		Private:         priv,
		DefaultBranch:   strField(m, "default_branch", 100),
		OpenIssuesCount: int(n),
	}
	if repo.FullName == "" {
		return SafeResult{}, errors.New("invalid response")
	}
	return SafeResult{Summary: "github ok", Data: map[string]interface{}{
		"full_name":         repo.FullName,
		"description":       repo.Description,
		"private":           repo.Private,
		"default_branch":    repo.DefaultBranch,
		"open_issues_count": repo.OpenIssuesCount,
	}}, nil
}
