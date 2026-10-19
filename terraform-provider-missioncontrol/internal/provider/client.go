package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// APIError is an HTTP error from Mission Control.
type APIError struct {
	Status int
	Body   string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("mission control API %d: %s", e.Status, e.Body)
}

func notFound(err error) bool {
	ae, ok := err.(*APIError)
	return ok && ae.Status == http.StatusNotFound
}

// Client is a small JSON client for the v1 API.
type Client struct {
	Base  string
	Token string
	HTTP  *http.Client
}

func (c *Client) do(ctx context.Context, method, path string, in any, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(c.Base, "/")+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("X-Mission-Control-Client", "terraform")
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	hc := c.HTTP
	if hc == nil {
		hc = http.DefaultClient
	}
	res, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	b, err := io.ReadAll(res.Body)
	if err != nil {
		return err
	}
	if res.StatusCode == http.StatusNoContent {
		return nil
	}
	if res.StatusCode >= 300 {
		return &APIError{Status: res.StatusCode, Body: strings.TrimSpace(string(b))}
	}
	if out != nil && len(bytes.TrimSpace(b)) > 0 {
		if err := json.Unmarshal(b, out); err != nil {
			return fmt.Errorf("decode %s: %w", path, err)
		}
	}
	return nil
}

type recipeRepoAPI struct {
	ID        string `json:"id,omitempty"`
	Name      string `json:"name"`
	URL       string `json:"url"`
	Ref       string `json:"ref"`
	ManagedBy string `json:"managed_by,omitempty"`
}

func (c *Client) CreateRecipeRepo(ctx context.Context, in recipeRepoAPI) (recipeRepoAPI, error) {
	var out recipeRepoAPI
	err := c.do(ctx, http.MethodPost, "/api/v1/recipe-repos", in, &out)
	return out, err
}
func (c *Client) GetRecipeRepo(ctx context.Context, id string) (recipeRepoAPI, error) {
	var out recipeRepoAPI
	err := c.do(ctx, http.MethodGet, "/api/v1/recipe-repos/"+id, nil, &out)
	return out, err
}
func (c *Client) UpdateRecipeRepo(ctx context.Context, id string, in recipeRepoAPI) (recipeRepoAPI, error) {
	var out recipeRepoAPI
	err := c.do(ctx, http.MethodPut, "/api/v1/recipe-repos/"+id, in, &out)
	return out, err
}
func (c *Client) DeleteRecipeRepo(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodDelete, "/api/v1/recipe-repos/"+id, nil, nil)
}

type recipeAPI struct {
	ID           string          `json:"id,omitempty"`
	Identifier   string          `json:"identifier"`
	Name         string          `json:"name"`
	RepoID       *string         `json:"repo_id"`
	Enabled      bool            `json:"enabled"`
	Override     string          `json:"override"`
	TrustInfo    json.RawMessage `json:"trust_info"`
	RunnerPoolID *string         `json:"runner_pool_id"`
	Labels       []string        `json:"labels"`
	ManagedBy    string          `json:"managed_by,omitempty"`
}

func (c *Client) CreateRecipe(ctx context.Context, in recipeAPI) (recipeAPI, error) {
	var out recipeAPI
	err := c.do(ctx, http.MethodPost, "/api/v1/recipes", in, &out)
	return out, err
}
func (c *Client) GetRecipe(ctx context.Context, id string) (recipeAPI, error) {
	var out recipeAPI
	err := c.do(ctx, http.MethodGet, "/api/v1/recipes/"+id, nil, &out)
	return out, err
}
func (c *Client) UpdateRecipe(ctx context.Context, id string, in recipeAPI) (recipeAPI, error) {
	var out recipeAPI
	err := c.do(ctx, http.MethodPut, "/api/v1/recipes/"+id, in, &out)
	return out, err
}
func (c *Client) DeleteRecipe(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodDelete, "/api/v1/recipes/"+id, nil, nil)
}

type scheduleAPI struct {
	ID        string `json:"id,omitempty"`
	Name      string `json:"name"`
	RecipeID  string `json:"recipe_id"`
	Cron      string `json:"cron"`
	Timezone  string `json:"timezone,omitempty"`
	Enabled   bool   `json:"enabled"`
	ManagedBy string `json:"managed_by,omitempty"`
}

func (c *Client) CreateSchedule(ctx context.Context, in scheduleAPI) (scheduleAPI, error) {
	var out scheduleAPI
	err := c.do(ctx, http.MethodPost, "/api/v1/schedules", in, &out)
	return out, err
}
func (c *Client) GetSchedule(ctx context.Context, id string) (scheduleAPI, error) {
	var out scheduleAPI
	err := c.do(ctx, http.MethodGet, "/api/v1/schedules/"+id, nil, &out)
	return out, err
}
func (c *Client) UpdateSchedule(ctx context.Context, id string, in scheduleAPI) (scheduleAPI, error) {
	var out scheduleAPI
	err := c.do(ctx, http.MethodPut, "/api/v1/schedules/"+id, in, &out)
	return out, err
}
func (c *Client) DeleteSchedule(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodDelete, "/api/v1/schedules/"+id, nil, nil)
}

type pipelineAPI struct {
	ID                   string `json:"id,omitempty"`
	MaxConcurrency       int    `json:"max_concurrency"`
	PerRunnerParallelism int    `json:"per_runner_parallelism"`
	TimeoutSeconds       int    `json:"timeout_seconds"`
	MaxRetries           int    `json:"max_retries"`
	LeaseSeconds         int    `json:"lease_seconds"`
	ManagedBy            string `json:"managed_by,omitempty"`
}

func (c *Client) GetPipeline(ctx context.Context) (pipelineAPI, error) {
	var out pipelineAPI
	err := c.do(ctx, http.MethodGet, "/api/v1/pipeline-settings", nil, &out)
	return out, err
}
func (c *Client) UpdatePipeline(ctx context.Context, in pipelineAPI) (pipelineAPI, error) {
	var out pipelineAPI
	err := c.do(ctx, http.MethodPut, "/api/v1/pipeline-settings", in, &out)
	return out, err
}
func (c *Client) ResetPipeline(ctx context.Context) error {
	return c.do(ctx, http.MethodDelete, "/api/v1/pipeline-settings", nil, &pipelineAPI{})
}

type ruleAPI struct {
	ID          string `json:"id,omitempty"`
	Name        string `json:"name"`
	FromCatalog string `json:"from_catalog"`
	ToCatalog   string `json:"to_catalog"`
	SoakDays    int    `json:"soak_days"`
	ManualHold  bool   `json:"manual_hold"`
	Enabled     bool   `json:"enabled"`
	ManagedBy   string `json:"managed_by,omitempty"`
}

func (c *Client) CreateRule(ctx context.Context, in ruleAPI) (ruleAPI, error) {
	var out ruleAPI
	err := c.do(ctx, http.MethodPost, "/api/v1/promotion-rules", in, &out)
	return out, err
}
func (c *Client) GetRule(ctx context.Context, id string) (ruleAPI, error) {
	var out ruleAPI
	err := c.do(ctx, http.MethodGet, "/api/v1/promotion-rules/"+id, nil, &out)
	return out, err
}
func (c *Client) UpdateRule(ctx context.Context, id string, in ruleAPI) (ruleAPI, error) {
	var out ruleAPI
	err := c.do(ctx, http.MethodPut, "/api/v1/promotion-rules/"+id, in, &out)
	return out, err
}
func (c *Client) DeleteRule(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodDelete, "/api/v1/promotion-rules/"+id, nil, nil)
}

type poolAPI struct {
	ID          string   `json:"id,omitempty"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Labels      []string `json:"labels"`
	ManagedBy   string   `json:"managed_by,omitempty"`
}

func (c *Client) CreatePool(ctx context.Context, in poolAPI) (poolAPI, error) {
	var out poolAPI
	err := c.do(ctx, http.MethodPost, "/api/v1/runner-pools", in, &out)
	return out, err
}
func (c *Client) GetPool(ctx context.Context, id string) (poolAPI, error) {
	var out poolAPI
	err := c.do(ctx, http.MethodGet, "/api/v1/runner-pools/"+id, nil, &out)
	return out, err
}
func (c *Client) UpdatePool(ctx context.Context, id string, in poolAPI) (poolAPI, error) {
	var out poolAPI
	err := c.do(ctx, http.MethodPut, "/api/v1/runner-pools/"+id, in, &out)
	return out, err
}
func (c *Client) DeletePool(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodDelete, "/api/v1/runner-pools/"+id, nil, nil)
}

type manifestAPI struct {
	ID                string   `json:"id,omitempty"`
	Name              string   `json:"name"`
	Catalogs          []string `json:"catalogs"`
	IncludedManifests []string `json:"included_manifests"`
	ManagedInstalls   []string `json:"managed_installs"`
	OptionalInstalls  []string `json:"optional_installs"`
	ManagedUninstalls []string `json:"managed_uninstalls"`
	ManagedBy         string   `json:"managed_by,omitempty"`
}

func (c *Client) CreateManifest(ctx context.Context, in manifestAPI) (manifestAPI, error) {
	var out manifestAPI
	err := c.do(ctx, http.MethodPost, "/api/v1/manifests", in, &out)
	return out, err
}
func (c *Client) GetManifest(ctx context.Context, id string) (manifestAPI, error) {
	var out manifestAPI
	err := c.do(ctx, http.MethodGet, "/api/v1/manifests/"+id, nil, &out)
	return out, err
}
func (c *Client) UpdateManifest(ctx context.Context, id string, in manifestAPI) (manifestAPI, error) {
	var out manifestAPI
	err := c.do(ctx, http.MethodPut, "/api/v1/manifests/"+id, in, &out)
	return out, err
}
func (c *Client) DeleteManifest(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodDelete, "/api/v1/manifests/"+id, nil, nil)
}
