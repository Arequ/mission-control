package provider

import (
	"context"
	"net/http"
	"os"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// New returns a provider factory.
func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &mcProvider{version: version}
	}
}

type mcProvider struct {
	version string
}

func (p *mcProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "missioncontrol"
	resp.Version = p.version
}

func (p *mcProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages Mission Control configuration. The service has no in-app editor; this provider is the write path.",
		Attributes: map[string]schema.Attribute{
			"endpoint": schema.StringAttribute{
				Description: "Base URL of Mission Control, for example http://localhost:8080. Overrides MISSIONCONTROL_ENDPOINT.",
				Optional:    true,
			},
			"token": schema.StringAttribute{
				Description: "API token with config:write. Overrides MISSIONCONTROL_TOKEN.",
				Optional:    true,
				Sensitive:   true,
			},
		},
	}
}

type providerConfig struct {
	Endpoint types.String `tfsdk:"endpoint"`
	Token    types.String `tfsdk:"token"`
}

func (p *mcProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var cfg providerConfig
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}
	endpoint := os.Getenv("MISSIONCONTROL_ENDPOINT")
	token := os.Getenv("MISSIONCONTROL_TOKEN")
	if !cfg.Endpoint.IsNull() && !cfg.Endpoint.IsUnknown() {
		endpoint = cfg.Endpoint.ValueString()
	}
	if !cfg.Token.IsNull() && !cfg.Token.IsUnknown() {
		token = cfg.Token.ValueString()
	}
	if endpoint == "" || token == "" {
		if cfg.Endpoint.IsUnknown() || cfg.Token.IsUnknown() {
			return
		}
		resp.Diagnostics.AddError("missing provider configuration", "Set endpoint and token, or MISSIONCONTROL_ENDPOINT and MISSIONCONTROL_TOKEN.")
		return
	}
	client := &Client{Base: endpoint, Token: token, HTTP: &http.Client{}}
	resp.ResourceData = client
	resp.DataSourceData = client
}

func (p *mcProvider) Resources(_ context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		newRecipeRepoResource,
		newRecipeResource,
		newScheduleResource,
		newPipelineResource,
		newPromotionRuleResource,
		newRunnerPoolResource,
		newManifestResource,
		newOsqueryQueryResource,
		newOsqueryPackResource,
		newOsqueryLabelResource,
		newEnrollSecretResource,
		newSourceConnectorResource,
		newLogViewResource,
		newVulnerabilitySettingsResource,
	}
}

func (p *mcProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{newLogViewDataSource}
}

func configureClient(req resource.ConfigureRequest, resp *resource.ConfigureResponse) *Client {
	if req.ProviderData == nil {
		return nil
	}
	client, ok := req.ProviderData.(*Client)
	if !ok {
		resp.Diagnostics.AddError("unexpected provider data", "expected *Client")
		return nil
	}
	return client
}
