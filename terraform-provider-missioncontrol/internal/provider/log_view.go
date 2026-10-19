package provider

import (
	"context"
	"net/http"
	"net/url"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	dsschema "github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64default"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

func newLogViewResource() resource.Resource { return &logViewResource{} }

type logViewResource struct{ client *Client }

func (r *logViewResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_log_view"
}

func (r *logViewResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.client = configureClient(req, resp)
}

func (r *logViewResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "A named log view: one or more Elastic queries whose message lines are merged by time. There is no query builder in the UI. elastic_api_key is write-only. An empty or omitted key on update keeps the stored value. A connector_id reuses that connector's Elastic URL and API key when this view does not set its own. Device-scoped views bind {{serial}}, {{hostname}}, and {{hardware_uuid}} from the device record.",
		Attributes: map[string]schema.Attribute{
			"id":                      schema.StringAttribute{Computed: true, PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}},
			"name":                    schema.StringAttribute{Required: true},
			"description":             schema.StringAttribute{Optional: true, Computed: true, Default: stringdefault.StaticString("")},
			"default_window":          schema.StringAttribute{Optional: true, Computed: true, Default: stringdefault.StaticString("1h"), Description: "15m, 1h, 6h, 24h, 7d, or 30d. The viewer opens on this window."},
			"max_lines":               schema.Int64Attribute{Optional: true, Computed: true, Default: int64default.StaticInt64(5000), Description: "Cap on lines returned for one viewing session. 1–100000."},
			"device_scoped":           schema.BoolAttribute{Optional: true, Computed: true, Default: booldefault.StaticBool(false), Description: "When true, a run requires a device and the KQL must use {{serial}}, {{hostname}}, or {{hardware_uuid}}."},
			"time_zone":               schema.StringAttribute{Optional: true, Computed: true, Default: stringdefault.StaticString("UTC"), Description: "IANA zone for timestamp values that do not include an offset."},
			"elastic_url":             schema.StringAttribute{Optional: true, Computed: true, Default: stringdefault.StaticString(""), Description: "Elasticsearch origin. Optional when connector_id is set. No userinfo."},
			"elastic_api_key":         schema.StringAttribute{Optional: true, Sensitive: true, WriteOnly: true, Description: "Write-only Elasticsearch ApiKey. Never stored in state and never returned by the API."},
			"connector_id":            schema.StringAttribute{Optional: true, Computed: true, Default: stringdefault.StaticString(""), Description: "Source connector whose Elastic URL and API key this view reuses."},
			"managed_by":              schema.StringAttribute{Optional: true, Computed: true, Default: stringdefault.StaticString("terraform")},
			"credentials_fingerprint": schema.StringAttribute{Computed: true, PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}, Description: "SHA-256 of the configured write-only API key. Null after import only when configuration also omits it."},
		},
		Blocks: map[string]schema.Block{
			"source": schema.ListNestedBlock{
				Description: "Indexes read by this view, in merge order. Equal timestamps keep this order, then the sequence field.",
				NestedObject: schema.NestedBlockObject{Attributes: map[string]schema.Attribute{
					"label":           schema.StringAttribute{Required: true, Description: "Short name shown beside the line."},
					"color":           schema.StringAttribute{Optional: true, Computed: true, Default: stringdefault.StaticString(""), Description: "#rrggbb gutter color."},
					"index_pattern":   schema.StringAttribute{Required: true},
					"kql":             schema.StringAttribute{Optional: true, Computed: true, Default: stringdefault.StaticString(""), Description: "KQL subset. Placeholders are quoted and cannot change the query shape."},
					"message_field":   schema.StringAttribute{Required: true},
					"timestamp_field": schema.StringAttribute{Required: true},
					"file_field":      schema.StringAttribute{Optional: true, Computed: true, Default: stringdefault.StaticString("")},
					"host_field":      schema.StringAttribute{Optional: true, Computed: true, Default: stringdefault.StaticString("")},
					"sequence_field":  schema.StringAttribute{Optional: true, Computed: true, Default: stringdefault.StaticString(""), Description: "Per-file offset. Lines in one file keep this order when timestamps are equal."},
				}},
			},
		},
	}
}

type logSourceModel struct {
	Label          types.String `tfsdk:"label"`
	Color          types.String `tfsdk:"color"`
	IndexPattern   types.String `tfsdk:"index_pattern"`
	KQL            types.String `tfsdk:"kql"`
	MessageField   types.String `tfsdk:"message_field"`
	TimestampField types.String `tfsdk:"timestamp_field"`
	FileField      types.String `tfsdk:"file_field"`
	HostField      types.String `tfsdk:"host_field"`
	SequenceField  types.String `tfsdk:"sequence_field"`
}

type logViewModel struct {
	ID                     types.String `tfsdk:"id"`
	Name                   types.String `tfsdk:"name"`
	Description            types.String `tfsdk:"description"`
	DefaultWindow          types.String `tfsdk:"default_window"`
	MaxLines               types.Int64  `tfsdk:"max_lines"`
	DeviceScoped           types.Bool   `tfsdk:"device_scoped"`
	TimeZone               types.String `tfsdk:"time_zone"`
	ElasticURL             types.String `tfsdk:"elastic_url"`
	ElasticAPIKey          types.String `tfsdk:"elastic_api_key"`
	ConnectorID            types.String `tfsdk:"connector_id"`
	ManagedBy              types.String `tfsdk:"managed_by"`
	CredentialsFingerprint types.String `tfsdk:"credentials_fingerprint"`
	Source                 types.List   `tfsdk:"source"`
}

func (m logViewModel) secrets() []types.String {
	return []types.String{m.ElasticAPIKey}
}

func (m logViewModel) api(ctx context.Context, cfg logViewModel) (logViewAPI, diag.Diagnostics) {
	sources, diags := sourceModels(ctx, m.Source)
	api := logViewAPI{
		Name: m.Name.ValueString(), Description: m.Description.ValueString(),
		DefaultWindow: m.DefaultWindow.ValueString(), MaxLines: int(m.MaxLines.ValueInt64()),
		DeviceScoped: m.DeviceScoped.ValueBool(), TimeZone: m.TimeZone.ValueString(),
		ElasticURL: m.ElasticURL.ValueString(), ElasticAPIKey: configuredSecret(cfg.ElasticAPIKey),
		ConnectorID: m.ConnectorID.ValueString(), ManagedBy: m.ManagedBy.ValueString(),
		Sources: make([]logSourceAPI, len(sources)),
	}
	for i, src := range sources {
		api.Sources[i] = logSourceAPI{
			Label: src.Label.ValueString(), Color: src.Color.ValueString(),
			IndexPattern: src.IndexPattern.ValueString(), KQL: src.KQL.ValueString(),
			MessageField: src.MessageField.ValueString(), TimestampField: src.TimestampField.ValueString(),
			FileField: src.FileField.ValueString(), HostField: src.HostField.ValueString(),
			SequenceField: src.SequenceField.ValueString(),
		}
	}
	return api, diags
}

func modelLogView(ctx context.Context, in logViewAPI, fingerprint types.String) (logViewModel, diag.Diagnostics) {
	list, diags := sourcesFromAPI(ctx, in.Sources)
	return logViewModel{
		ID: types.StringValue(in.ID), Name: types.StringValue(in.Name),
		Description: types.StringValue(in.Description), DefaultWindow: types.StringValue(in.DefaultWindow),
		MaxLines: types.Int64Value(int64(in.MaxLines)), DeviceScoped: types.BoolValue(in.DeviceScoped),
		TimeZone: types.StringValue(in.TimeZone), ElasticURL: types.StringValue(in.ElasticURL),
		ConnectorID: types.StringValue(in.ConnectorID), ManagedBy: types.StringValue(in.ManagedBy),
		CredentialsFingerprint: fingerprint, Source: list,
	}, diags
}

func (r *logViewResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan, cfg logViewModel
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
	out, err := r.client.CreateLogView(ctx, body)
	if err != nil {
		resp.Diagnostics.AddError("create log view", err.Error())
		return
	}
	state, diags := modelLogView(ctx, out, types.StringValue(credentialFingerprint(configuredSecret(cfg.ElasticAPIKey))))
	resp.Diagnostics.Append(diags...)
	resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
}

func (r *logViewResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state logViewModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	out, err := r.client.GetLogView(ctx, state.ID.ValueString())
	if notFound(err) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("read log view", err.Error())
		return
	}
	fingerprint := types.StringNull()
	if !state.CredentialsFingerprint.IsNull() && !state.CredentialsFingerprint.IsUnknown() {
		fingerprint = state.CredentialsFingerprint
	}
	next, diags := modelLogView(ctx, out, fingerprint)
	resp.Diagnostics.Append(diags...)
	resp.Diagnostics.Append(resp.State.Set(ctx, next)...)
}

func (r *logViewResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, cfg logViewModel
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
	out, err := r.client.UpdateLogView(ctx, plan.ID.ValueString(), body)
	if err != nil {
		resp.Diagnostics.AddError("update log view", err.Error())
		return
	}
	fingerprint := plan.CredentialsFingerprint
	if fingerprint.IsNull() || fingerprint.IsUnknown() {
		fingerprint = types.StringValue(credentialFingerprint(configuredSecret(cfg.ElasticAPIKey)))
	}
	state, diags := modelLogView(ctx, out, fingerprint)
	resp.Diagnostics.Append(diags...)
	resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
}

func (r *logViewResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state logViewModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.DeleteLogView(ctx, state.ID.ValueString()); err != nil && !notFound(err) {
		resp.Diagnostics.AddError("delete log view", err.Error())
	}
}

func (r *logViewResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

func (r *logViewResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	if req.Plan.Raw.IsNull() {
		return
	}
	var cfg, plan logViewModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	plan.ElasticAPIKey = types.StringNull()
	prior := types.StringNull()
	if !req.State.Raw.IsNull() {
		var state logViewModel
		resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
		if resp.Diagnostics.HasError() {
			return
		}
		prior = state.CredentialsFingerprint
	}
	plan.CredentialsFingerprint = nextFingerprint(req.State.Raw.IsNull(), prior, cfg.secrets())
	resp.Diagnostics.Append(resp.Plan.Set(ctx, plan)...)
}

func newLogViewDataSource() datasource.DataSource { return &logViewDataSource{} }

type logViewDataSource struct{ client *Client }

func (d *logViewDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_log_view"
}

func (d *logViewDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	client, ok := req.ProviderData.(*Client)
	if !ok {
		resp.Diagnostics.AddError("unexpected provider data", "expected *Client")
		return
	}
	d.client = client
}

func (d *logViewDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = dsschema.Schema{
		Description: "Reads one log view by id or name. Credentials are not returned.",
		Attributes: map[string]dsschema.Attribute{
			"id":                  dsschema.StringAttribute{Optional: true, Computed: true, Description: "View id. When set, the lookup uses the id."},
			"name":                dsschema.StringAttribute{Optional: true, Computed: true},
			"description":         dsschema.StringAttribute{Computed: true},
			"default_window":      dsschema.StringAttribute{Computed: true},
			"max_lines":           dsschema.Int64Attribute{Computed: true},
			"device_scoped":       dsschema.BoolAttribute{Computed: true},
			"time_zone":           dsschema.StringAttribute{Computed: true},
			"elastic_url":         dsschema.StringAttribute{Computed: true},
			"connector_id":        dsschema.StringAttribute{Computed: true},
			"managed_by":          dsschema.StringAttribute{Computed: true},
			"has_elastic_api_key": dsschema.BoolAttribute{Computed: true},
		},
		Blocks: map[string]dsschema.Block{
			"source": dsschema.ListNestedBlock{
				NestedObject: dsschema.NestedBlockObject{Attributes: map[string]dsschema.Attribute{
					"label":           dsschema.StringAttribute{Computed: true},
					"color":           dsschema.StringAttribute{Computed: true},
					"index_pattern":   dsschema.StringAttribute{Computed: true},
					"kql":             dsschema.StringAttribute{Computed: true},
					"message_field":   dsschema.StringAttribute{Computed: true},
					"timestamp_field": dsschema.StringAttribute{Computed: true},
					"file_field":      dsschema.StringAttribute{Computed: true},
					"host_field":      dsschema.StringAttribute{Computed: true},
					"sequence_field":  dsschema.StringAttribute{Computed: true},
				}},
			},
		},
	}
}

type logViewDataModel struct {
	ID               types.String `tfsdk:"id"`
	Name             types.String `tfsdk:"name"`
	Description      types.String `tfsdk:"description"`
	DefaultWindow    types.String `tfsdk:"default_window"`
	MaxLines         types.Int64  `tfsdk:"max_lines"`
	DeviceScoped     types.Bool   `tfsdk:"device_scoped"`
	TimeZone         types.String `tfsdk:"time_zone"`
	ElasticURL       types.String `tfsdk:"elastic_url"`
	ConnectorID      types.String `tfsdk:"connector_id"`
	ManagedBy        types.String `tfsdk:"managed_by"`
	HasElasticAPIKey types.Bool   `tfsdk:"has_elastic_api_key"`
	Source           types.List   `tfsdk:"source"`
}

func (d *logViewDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var cfg logViewDataModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if d.client == nil {
		resp.Diagnostics.AddError("missing provider configuration", "Set endpoint and token.")
		return
	}
	id := ""
	name := ""
	if !cfg.ID.IsNull() && !cfg.ID.IsUnknown() {
		id = cfg.ID.ValueString()
	}
	if !cfg.Name.IsNull() && !cfg.Name.IsUnknown() {
		name = cfg.Name.ValueString()
	}
	var out logViewAPI
	switch {
	case id != "":
		got, err := d.client.GetLogView(ctx, id)
		if err != nil {
			resp.Diagnostics.AddError("read log view", err.Error())
			return
		}
		out = got
	case name != "":
		list, err := d.client.ListLogViews(ctx, name)
		if err != nil {
			resp.Diagnostics.AddError("read log view", err.Error())
			return
		}
		if len(list) != 1 {
			resp.Diagnostics.AddError("read log view", "no log view named "+name)
			return
		}
		out = list[0]
	default:
		resp.Diagnostics.AddError("read log view", "set id or name")
		return
	}
	list, diags := sourcesFromAPI(ctx, out.Sources)
	resp.Diagnostics.Append(diags...)
	state := logViewDataModel{
		ID: types.StringValue(out.ID), Name: types.StringValue(out.Name),
		Description: types.StringValue(out.Description), DefaultWindow: types.StringValue(out.DefaultWindow),
		MaxLines: types.Int64Value(int64(out.MaxLines)), DeviceScoped: types.BoolValue(out.DeviceScoped),
		TimeZone: types.StringValue(out.TimeZone), ElasticURL: types.StringValue(out.ElasticURL),
		ConnectorID: types.StringValue(out.ConnectorID), ManagedBy: types.StringValue(out.ManagedBy),
		HasElasticAPIKey: types.BoolValue(out.HasElasticAPIKey), Source: list,
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func sourceModels(ctx context.Context, list types.List) ([]logSourceModel, diag.Diagnostics) {
	if list.IsNull() || list.IsUnknown() {
		return nil, nil
	}
	var out []logSourceModel
	diags := list.ElementsAs(ctx, &out, false)
	return out, diags
}

var logSourceTypes = map[string]attr.Type{
	"label":           types.StringType,
	"color":           types.StringType,
	"index_pattern":   types.StringType,
	"kql":             types.StringType,
	"message_field":   types.StringType,
	"timestamp_field": types.StringType,
	"file_field":      types.StringType,
	"host_field":      types.StringType,
	"sequence_field":  types.StringType,
}

func sourcesFromAPI(ctx context.Context, in []logSourceAPI) (types.List, diag.Diagnostics) {
	if in == nil {
		in = []logSourceAPI{}
	}
	objs := make([]logSourceModel, len(in))
	for i, src := range in {
		objs[i] = logSourceModel{
			Label: types.StringValue(src.Label), Color: types.StringValue(src.Color),
			IndexPattern: types.StringValue(src.IndexPattern), KQL: types.StringValue(src.KQL),
			MessageField: types.StringValue(src.MessageField), TimestampField: types.StringValue(src.TimestampField),
			FileField: types.StringValue(src.FileField), HostField: types.StringValue(src.HostField),
			SequenceField: types.StringValue(src.SequenceField),
		}
	}
	return types.ListValueFrom(ctx, types.ObjectType{AttrTypes: logSourceTypes}, objs)
}

type logSourceAPI struct {
	Label          string `json:"label"`
	Color          string `json:"color"`
	IndexPattern   string `json:"index_pattern"`
	KQL            string `json:"kql"`
	MessageField   string `json:"message_field"`
	TimestampField string `json:"timestamp_field"`
	FileField      string `json:"file_field"`
	HostField      string `json:"host_field"`
	SequenceField  string `json:"sequence_field"`
}

type logViewAPI struct {
	ID               string         `json:"id,omitempty"`
	Name             string         `json:"name"`
	Description      string         `json:"description"`
	DefaultWindow    string         `json:"default_window"`
	MaxLines         int            `json:"max_lines"`
	DeviceScoped     bool           `json:"device_scoped"`
	TimeZone         string         `json:"time_zone"`
	ElasticURL       string         `json:"elastic_url"`
	ElasticAPIKey    string         `json:"elastic_api_key,omitempty"`
	ConnectorID      string         `json:"connector_id"`
	ManagedBy        string         `json:"managed_by,omitempty"`
	HasElasticAPIKey bool           `json:"has_elastic_api_key,omitempty"`
	Sources          []logSourceAPI `json:"sources"`
}

func (c *Client) CreateLogView(ctx context.Context, in logViewAPI) (logViewAPI, error) {
	var out logViewAPI
	err := c.do(ctx, http.MethodPost, "/api/v1/log-views", in, &out)
	return out, err
}

func (c *Client) GetLogView(ctx context.Context, id string) (logViewAPI, error) {
	var out logViewAPI
	err := c.do(ctx, http.MethodGet, "/api/v1/log-views/"+url.PathEscape(id), nil, &out)
	return out, err
}

func (c *Client) UpdateLogView(ctx context.Context, id string, in logViewAPI) (logViewAPI, error) {
	var out logViewAPI
	err := c.do(ctx, http.MethodPut, "/api/v1/log-views/"+url.PathEscape(id), in, &out)
	return out, err
}

func (c *Client) DeleteLogView(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodDelete, "/api/v1/log-views/"+url.PathEscape(id), nil, nil)
}

func (c *Client) ListLogViews(ctx context.Context, name string) ([]logViewAPI, error) {
	path := "/api/v1/log-views"
	if name != "" {
		path += "?name=" + url.QueryEscape(name)
	}
	var out struct {
		Views []logViewAPI `json:"views"`
	}
	err := c.do(ctx, http.MethodGet, path, nil, &out)
	return out.Views, err
}
