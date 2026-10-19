package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64default"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/mapdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

func newSourceConnectorResource() resource.Resource { return &sourceConnectorResource{} }

type sourceConnectorResource struct{ client *Client }

func (r *sourceConnectorResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_source_connector"
}

func (r *sourceConnectorResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.client = configureClient(req, resp)
}

func (r *sourceConnectorResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "A security-source connector. osquery and munki use mode native. CrowdStrike and Kolide use mode api. Rapid7, Netskope, Proofpoint, and BlastShield use mode elastic against an index the organization already ships. client_secret, api_token, and elastic_api_key are write-only: Terraform sends them and the API never returns them. An empty or omitted credential on update keeps the stored value. After import, a configured credential plans one apply that records credentials_fingerprint. Later rotations diff against that hash. Omitting the credential in configuration does not plan an update.",
		Attributes: map[string]schema.Attribute{
			"id":                      schema.StringAttribute{Computed: true, PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}},
			"name":                    schema.StringAttribute{Required: true},
			"source":                  schema.StringAttribute{Required: true, Description: "osquery, munki, crowdstrike, rapid7, netskope, proofpoint, blastshield, or kolide. One connector per source."},
			"mode":                    schema.StringAttribute{Required: true, Description: "native, api, or elastic. native is only valid for osquery and munki."},
			"enabled":                 schema.BoolAttribute{Optional: true, Computed: true, Default: booldefault.StaticBool(true)},
			"interval_seconds":        schema.Int64Attribute{Optional: true, Computed: true, Default: int64default.StaticInt64(900), Description: "How often a poller may run. 60–604800."},
			"stale_after_seconds":     schema.Int64Attribute{Optional: true, Computed: true, Default: int64default.StaticInt64(86400), Description: "A snapshot older than this is stale. 60–31536000."},
			"base_url":                schema.StringAttribute{Optional: true, Computed: true, Default: stringdefault.StaticString(""), Description: "Vendor API origin. Required for mode api. No userinfo."},
			"client_id":               schema.StringAttribute{Optional: true, Computed: true, Default: stringdefault.StaticString(""), Description: "OAuth client id for CrowdStrike. Not a secret."},
			"client_secret":           schema.StringAttribute{Optional: true, Sensitive: true, WriteOnly: true, Description: "Write-only OAuth client secret. Never stored in state and never returned by the API."},
			"api_token":               schema.StringAttribute{Optional: true, Sensitive: true, WriteOnly: true, Description: "Write-only bearer token for Kolide and the API stubs."},
			"elastic_url":             schema.StringAttribute{Optional: true, Computed: true, Default: stringdefault.StaticString(""), Description: "Elasticsearch origin. Required for mode elastic. No userinfo."},
			"elastic_api_key":         schema.StringAttribute{Optional: true, Sensitive: true, WriteOnly: true, Description: "Write-only Elasticsearch ApiKey. Sent as Authorization: ApiKey."},
			"index_pattern":           schema.StringAttribute{Optional: true, Computed: true, Default: stringdefault.StaticString("")},
			"query":                   schema.StringAttribute{Optional: true, Computed: true, Default: stringdefault.StaticString(""), Description: "KQL or Elasticsearch DSL."},
			"query_language":          schema.StringAttribute{Optional: true, Computed: true, Default: stringdefault.StaticString("kql"), Description: "kql or dsl."},
			"time_field":              schema.StringAttribute{Optional: true, Computed: true, Default: stringdefault.StaticString("@timestamp")},
			"time_zone":               schema.StringAttribute{Optional: true, Computed: true, Default: stringdefault.StaticString("UTC"), Description: "IANA zone for time_field values that do not include an offset. Default UTC."},
			"field_map":               schema.MapAttribute{ElementType: types.StringType, Optional: true, Computed: true, Default: mapdefault.StaticValue(types.MapValueMust(types.StringType, map[string]attr.Value{})), Description: "Event field path for each normalized key: native_id, serial, hardware_uuid, mac, hostname, primary_user, os_version, ip_address, agent_version, last_seen."},
			"managed_by":              schema.StringAttribute{Optional: true, Computed: true, Default: stringdefault.StaticString("terraform")},
			"credentials_fingerprint": schema.StringAttribute{Computed: true, PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}, Description: "SHA-256 of the configured write-only credentials. Null after import only when configuration also omits them. When configuration has a credential, the next plan records the hash so a later rotation is visible."},
		},
	}
}

type sourceConnectorModel struct {
	ID                     types.String `tfsdk:"id"`
	Name                   types.String `tfsdk:"name"`
	Source                 types.String `tfsdk:"source"`
	Mode                   types.String `tfsdk:"mode"`
	Enabled                types.Bool   `tfsdk:"enabled"`
	IntervalSeconds        types.Int64  `tfsdk:"interval_seconds"`
	StaleAfterSeconds      types.Int64  `tfsdk:"stale_after_seconds"`
	BaseURL                types.String `tfsdk:"base_url"`
	ClientID               types.String `tfsdk:"client_id"`
	ClientSecret           types.String `tfsdk:"client_secret"`
	APIToken               types.String `tfsdk:"api_token"`
	ElasticURL             types.String `tfsdk:"elastic_url"`
	ElasticAPIKey          types.String `tfsdk:"elastic_api_key"`
	IndexPattern           types.String `tfsdk:"index_pattern"`
	Query                  types.String `tfsdk:"query"`
	QueryLanguage          types.String `tfsdk:"query_language"`
	TimeField              types.String `tfsdk:"time_field"`
	TimeZone               types.String `tfsdk:"time_zone"`
	FieldMap               types.Map    `tfsdk:"field_map"`
	ManagedBy              types.String `tfsdk:"managed_by"`
	CredentialsFingerprint types.String `tfsdk:"credentials_fingerprint"`
}

func (m sourceConnectorModel) secrets() []types.String {
	return []types.String{m.ClientSecret, m.APIToken, m.ElasticAPIKey}
}

func (m sourceConnectorModel) api(ctx context.Context, cfg sourceConnectorModel) (connectorAPI, diag.Diagnostics) {
	fieldMap, diags := stringMap(ctx, m.FieldMap)
	api := connectorAPI{
		Name: m.Name.ValueString(), Source: m.Source.ValueString(), Mode: m.Mode.ValueString(),
		Enabled: m.Enabled.ValueBool(), IntervalSeconds: int(m.IntervalSeconds.ValueInt64()),
		StaleAfterSeconds: int(m.StaleAfterSeconds.ValueInt64()),
		BaseURL:           m.BaseURL.ValueString(), ClientID: m.ClientID.ValueString(),
		ClientSecret: configuredSecret(cfg.ClientSecret), APIToken: configuredSecret(cfg.APIToken),
		ElasticURL: m.ElasticURL.ValueString(), ElasticAPIKey: configuredSecret(cfg.ElasticAPIKey),
		IndexPattern: m.IndexPattern.ValueString(), Query: m.Query.ValueString(),
		QueryLanguage: m.QueryLanguage.ValueString(), TimeField: m.TimeField.ValueString(),
		TimeZone: m.TimeZone.ValueString(),
		FieldMap: fieldMap, ManagedBy: m.ManagedBy.ValueString(),
	}
	return api, diags
}

func modelConnector(ctx context.Context, in connectorAPI, fingerprint types.String) (sourceConnectorModel, diag.Diagnostics) {
	fieldMap, diags := types.MapValueFrom(ctx, types.StringType, in.FieldMap)
	if in.FieldMap == nil {
		fieldMap = types.MapValueMust(types.StringType, map[string]attr.Value{})
		diags = nil
	}
	return sourceConnectorModel{
		ID: types.StringValue(in.ID), Name: types.StringValue(in.Name), Source: types.StringValue(in.Source),
		Mode: types.StringValue(in.Mode), Enabled: types.BoolValue(in.Enabled),
		IntervalSeconds: types.Int64Value(int64(in.IntervalSeconds)), StaleAfterSeconds: types.Int64Value(int64(in.StaleAfterSeconds)),
		BaseURL: types.StringValue(in.BaseURL), ClientID: types.StringValue(in.ClientID),
		ElasticURL: types.StringValue(in.ElasticURL), IndexPattern: types.StringValue(in.IndexPattern),
		Query: types.StringValue(in.Query), QueryLanguage: types.StringValue(in.QueryLanguage),
		TimeField: types.StringValue(in.TimeField), TimeZone: types.StringValue(in.TimeZone),
		FieldMap: fieldMap, ManagedBy: types.StringValue(in.ManagedBy),
		CredentialsFingerprint: fingerprint,
	}, diags
}

func (r *sourceConnectorResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan, cfg sourceConnectorModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}
	body, diags := plan.api(ctx, cfg)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	out, err := r.client.CreateConnector(ctx, body)
	if err != nil {
		resp.Diagnostics.AddError("create source connector", err.Error())
		return
	}
	state, diags := modelConnector(ctx, out, types.StringValue(credentialFingerprint(configuredSecret(cfg.ClientSecret), configuredSecret(cfg.APIToken), configuredSecret(cfg.ElasticAPIKey))))
	resp.Diagnostics.Append(diags...)
	resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
}

func (r *sourceConnectorResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state sourceConnectorModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	out, err := r.client.GetConnector(ctx, state.ID.ValueString())
	if notFound(err) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("read source connector", err.Error())
		return
	}
	fingerprint := types.StringNull()
	if !state.CredentialsFingerprint.IsNull() && !state.CredentialsFingerprint.IsUnknown() {
		fingerprint = state.CredentialsFingerprint
	}
	next, diags := modelConnector(ctx, out, fingerprint)
	resp.Diagnostics.Append(diags...)
	resp.Diagnostics.Append(resp.State.Set(ctx, next)...)
}

func (r *sourceConnectorResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, cfg sourceConnectorModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}
	body, diags := plan.api(ctx, cfg)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	out, err := r.client.UpdateConnector(ctx, plan.ID.ValueString(), body)
	if err != nil {
		resp.Diagnostics.AddError("update source connector", err.Error())
		return
	}
	fingerprint := plan.CredentialsFingerprint
	if fingerprint.IsNull() || fingerprint.IsUnknown() {
		fingerprint = types.StringValue(credentialFingerprint(configuredSecret(cfg.ClientSecret), configuredSecret(cfg.APIToken), configuredSecret(cfg.ElasticAPIKey)))
	}
	state, diags := modelConnector(ctx, out, fingerprint)
	resp.Diagnostics.Append(diags...)
	resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
}

func (r *sourceConnectorResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state sourceConnectorModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.DeleteConnector(ctx, state.ID.ValueString()); err != nil && !notFound(err) {
		resp.Diagnostics.AddError("delete source connector", err.Error())
	}
}

func (r *sourceConnectorResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

func (r *sourceConnectorResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	if req.Plan.Raw.IsNull() {
		return
	}
	var cfg, plan sourceConnectorModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	plan.ClientSecret = types.StringNull()
	plan.APIToken = types.StringNull()
	plan.ElasticAPIKey = types.StringNull()
	prior := types.StringNull()
	if !req.State.Raw.IsNull() {
		var state sourceConnectorModel
		resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
		if resp.Diagnostics.HasError() {
			return
		}
		prior = state.CredentialsFingerprint
	}
	plan.CredentialsFingerprint = nextFingerprint(req.State.Raw.IsNull(), prior, cfg.secrets())
	resp.Diagnostics.Append(resp.Plan.Set(ctx, plan)...)
}

func stringMap(ctx context.Context, m types.Map) (map[string]string, diag.Diagnostics) {
	if m.IsNull() || m.IsUnknown() {
		return map[string]string{}, nil
	}
	out := map[string]string{}
	diags := m.ElementsAs(ctx, &out, false)
	if out == nil {
		out = map[string]string{}
	}
	return out, diags
}
