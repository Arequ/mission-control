package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64default"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/listdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

func int64FromPtr(v *int) types.Int64 {
	if v == nil {
		return types.Int64Null()
	}
	return types.Int64Value(int64(*v))
}

func intPtrFrom(v types.Int64) *int {
	if v.IsNull() || v.IsUnknown() {
		return nil
	}
	n := int(v.ValueInt64())
	return &n
}

type osqueryQueryResource struct{ client *Client }

func newOsqueryQueryResource() resource.Resource { return &osqueryQueryResource{} }

func (r *osqueryQueryResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_osquery_query"
}
func (r *osqueryQueryResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.client = configureClient(req, resp)
}

type osqueryQueryModel struct {
	ID          types.String `tfsdk:"id"`
	Name        types.String `tfsdk:"name"`
	Description types.String `tfsdk:"description"`
	SQL         types.String `tfsdk:"sql"`
	Platform    types.String `tfsdk:"platform"`
	Interval    types.Int64  `tfsdk:"interval"`
	Snapshot    types.Bool   `tfsdk:"snapshot"`
	Removed     types.Bool   `tfsdk:"removed"`
	Scheduled   types.Bool   `tfsdk:"scheduled"`
	ManagedBy   types.String `tfsdk:"managed_by"`
}

func (r *osqueryQueryResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "An osquery query. Set scheduled to place it on the global schedule. Packs reference queries by id.",
		Attributes: map[string]schema.Attribute{
			"id":          schema.StringAttribute{Computed: true, PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}},
			"name":        schema.StringAttribute{Required: true, Description: "Schedule name. Must not start with mc_."},
			"description": schema.StringAttribute{Optional: true, Computed: true, Default: stringdefault.StaticString("")},
			"sql":         schema.StringAttribute{Required: true, Description: "A single SELECT statement."},
			"platform":    schema.StringAttribute{Optional: true, Computed: true, Default: stringdefault.StaticString(""), Description: "Empty runs everywhere. Otherwise a comma-separated osquery platform list."},
			"interval":    schema.Int64Attribute{Optional: true, Computed: true, Default: int64default.StaticInt64(3600), Description: "Seconds between runs."},
			"snapshot":    schema.BoolAttribute{Optional: true, Computed: true, Default: booldefault.StaticBool(false), Description: "Snapshot results replace the row set. Differential is the default."},
			"removed":     schema.BoolAttribute{Optional: true, Computed: true, Default: booldefault.StaticBool(true), Description: "Log removed rows for differential queries."},
			"scheduled":   schema.BoolAttribute{Optional: true, Computed: true, Default: booldefault.StaticBool(false), Description: "Include the query on the global schedule, not only inside packs."},
			"managed_by":  schema.StringAttribute{Optional: true, Computed: true, Default: stringdefault.StaticString("terraform")},
		},
	}
}

func (m osqueryQueryModel) api() osqueryQueryAPI {
	return osqueryQueryAPI{
		Name: m.Name.ValueString(), Description: m.Description.ValueString(), SQL: m.SQL.ValueString(),
		Platform: m.Platform.ValueString(), Interval: int(m.Interval.ValueInt64()), Snapshot: m.Snapshot.ValueBool(),
		Removed: m.Removed.ValueBool(), Scheduled: m.Scheduled.ValueBool(), ManagedBy: m.ManagedBy.ValueString(),
	}
}

func modelOsqueryQuery(in osqueryQueryAPI) osqueryQueryModel {
	return osqueryQueryModel{
		ID: types.StringValue(in.ID), Name: types.StringValue(in.Name), Description: types.StringValue(in.Description),
		SQL: types.StringValue(in.SQL), Platform: types.StringValue(in.Platform), Interval: types.Int64Value(int64(in.Interval)),
		Snapshot: types.BoolValue(in.Snapshot), Removed: types.BoolValue(in.Removed), Scheduled: types.BoolValue(in.Scheduled),
		ManagedBy: types.StringValue(in.ManagedBy),
	}
}

func (r *osqueryQueryResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan osqueryQueryModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	out, err := r.client.CreateOsqueryQuery(ctx, plan.api())
	if err != nil {
		resp.Diagnostics.AddError("create osquery query", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, modelOsqueryQuery(out))...)
}
func (r *osqueryQueryResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state osqueryQueryModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	out, err := r.client.GetOsqueryQuery(ctx, state.ID.ValueString())
	if notFound(err) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("read osquery query", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, modelOsqueryQuery(out))...)
}
func (r *osqueryQueryResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan osqueryQueryModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	out, err := r.client.UpdateOsqueryQuery(ctx, plan.ID.ValueString(), plan.api())
	if err != nil {
		resp.Diagnostics.AddError("update osquery query", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, modelOsqueryQuery(out))...)
}
func (r *osqueryQueryResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state osqueryQueryModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.DeleteOsqueryQuery(ctx, state.ID.ValueString()); err != nil && !notFound(err) {
		resp.Diagnostics.AddError("delete osquery query", err.Error())
	}
}
func (r *osqueryQueryResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

type osqueryPackResource struct{ client *Client }

func newOsqueryPackResource() resource.Resource { return &osqueryPackResource{} }

func (r *osqueryPackResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_osquery_pack"
}
func (r *osqueryPackResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.client = configureClient(req, resp)
}

type osqueryPackModel struct {
	ID          types.String `tfsdk:"id"`
	Name        types.String `tfsdk:"name"`
	Description types.String `tfsdk:"description"`
	Platform    types.String `tfsdk:"platform"`
	Interval    types.Int64  `tfsdk:"interval"`
	Shard       types.Int64  `tfsdk:"shard"`
	Discovery   types.List   `tfsdk:"discovery"`
	Labels      types.List   `tfsdk:"labels"`
	QueryIDs    types.List   `tfsdk:"query_ids"`
	Enabled     types.Bool   `tfsdk:"enabled"`
	ManagedBy   types.String `tfsdk:"managed_by"`
}

func (r *osqueryPackResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "A pack of osquery queries delivered only to hosts in one of labels. An empty label list means every host. Each query keeps its own interval and snapshot mode unless interval is set here.",
		Attributes: map[string]schema.Attribute{
			"id":          schema.StringAttribute{Computed: true, PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}},
			"name":        schema.StringAttribute{Required: true},
			"description": schema.StringAttribute{Optional: true, Computed: true, Default: stringdefault.StaticString("")},
			"platform":    schema.StringAttribute{Optional: true, Computed: true, Default: stringdefault.StaticString("")},
			"interval":    schema.Int64Attribute{Optional: true, Description: "Overrides each query interval inside this pack. Omit to keep the query intervals."},
			"shard":       schema.Int64Attribute{Optional: true, Description: "osquery shard, 1-100."},
			"discovery":   schema.ListAttribute{ElementType: types.StringType, Optional: true, Computed: true, Default: listdefault.StaticValue(emptyList()), Description: "Queries that must return rows before the pack runs on a host."},
			"labels":      schema.ListAttribute{ElementType: types.StringType, Optional: true, Computed: true, Default: listdefault.StaticValue(emptyList()), Description: "Label names. Empty applies the pack to every host."},
			"query_ids":   schema.ListAttribute{ElementType: types.StringType, Optional: true, Computed: true, Default: listdefault.StaticValue(emptyList())},
			"enabled":     schema.BoolAttribute{Optional: true, Computed: true, Default: booldefault.StaticBool(true)},
			"managed_by":  schema.StringAttribute{Optional: true, Computed: true, Default: stringdefault.StaticString("terraform")},
		},
	}
}

func (m osqueryPackModel) api(ctx context.Context) (osqueryPackAPI, diag.Diagnostics) {
	var diags diag.Diagnostics
	api := osqueryPackAPI{
		Name: m.Name.ValueString(), Description: m.Description.ValueString(), Platform: m.Platform.ValueString(),
		Interval: intPtrFrom(m.Interval), Shard: intPtrFrom(m.Shard), Enabled: m.Enabled.ValueBool(), ManagedBy: m.ManagedBy.ValueString(),
	}
	var d diag.Diagnostics
	if api.Discovery, d = stringsFromList(ctx, m.Discovery); d.HasError() {
		diags.Append(d...)
	}
	if api.Labels, d = stringsFromList(ctx, m.Labels); d.HasError() {
		diags.Append(d...)
	}
	if api.QueryIDs, d = stringsFromList(ctx, m.QueryIDs); d.HasError() {
		diags.Append(d...)
	}
	return api, diags
}

func modelOsqueryPack(ctx context.Context, in osqueryPackAPI) (osqueryPackModel, diag.Diagnostics) {
	var diags diag.Diagnostics
	m := osqueryPackModel{
		ID: types.StringValue(in.ID), Name: types.StringValue(in.Name), Description: types.StringValue(in.Description),
		Platform: types.StringValue(in.Platform), Interval: int64FromPtr(in.Interval), Shard: int64FromPtr(in.Shard),
		Enabled: types.BoolValue(in.Enabled), ManagedBy: types.StringValue(in.ManagedBy),
	}
	var d diag.Diagnostics
	if m.Discovery, d = listOfStrings(ctx, in.Discovery); d.HasError() {
		diags.Append(d...)
	}
	if m.Labels, d = listOfStrings(ctx, in.Labels); d.HasError() {
		diags.Append(d...)
	}
	if m.QueryIDs, d = listOfStrings(ctx, in.QueryIDs); d.HasError() {
		diags.Append(d...)
	}
	return m, diags
}

func (r *osqueryPackResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan osqueryPackModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	body, diags := plan.api(ctx)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	out, err := r.client.CreateOsqueryPack(ctx, body)
	if err != nil {
		resp.Diagnostics.AddError("create osquery pack", err.Error())
		return
	}
	model, diags := modelOsqueryPack(ctx, out)
	resp.Diagnostics.Append(diags...)
	resp.Diagnostics.Append(resp.State.Set(ctx, model)...)
}
func (r *osqueryPackResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state osqueryPackModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	out, err := r.client.GetOsqueryPack(ctx, state.ID.ValueString())
	if notFound(err) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("read osquery pack", err.Error())
		return
	}
	model, diags := modelOsqueryPack(ctx, out)
	resp.Diagnostics.Append(diags...)
	resp.Diagnostics.Append(resp.State.Set(ctx, model)...)
}
func (r *osqueryPackResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan osqueryPackModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	body, diags := plan.api(ctx)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	out, err := r.client.UpdateOsqueryPack(ctx, plan.ID.ValueString(), body)
	if err != nil {
		resp.Diagnostics.AddError("update osquery pack", err.Error())
		return
	}
	model, diags := modelOsqueryPack(ctx, out)
	resp.Diagnostics.Append(diags...)
	resp.Diagnostics.Append(resp.State.Set(ctx, model)...)
}
func (r *osqueryPackResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state osqueryPackModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.DeleteOsqueryPack(ctx, state.ID.ValueString()); err != nil && !notFound(err) {
		resp.Diagnostics.AddError("delete osquery pack", err.Error())
	}
}
func (r *osqueryPackResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

type osqueryLabelResource struct{ client *Client }

func newOsqueryLabelResource() resource.Resource { return &osqueryLabelResource{} }

func (r *osqueryLabelResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_osquery_label"
}
func (r *osqueryLabelResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.client = configureClient(req, resp)
}

type osqueryLabelModel struct {
	ID          types.String `tfsdk:"id"`
	Name        types.String `tfsdk:"name"`
	Description types.String `tfsdk:"description"`
	Kind        types.String `tfsdk:"kind"`
	SQL         types.String `tfsdk:"sql"`
	Platform    types.String `tfsdk:"platform"`
	Serials     types.List   `tfsdk:"serials"`
	DeviceIDs   types.List   `tfsdk:"device_ids"`
	ManagedBy   types.String `tfsdk:"managed_by"`
}

func (r *osqueryLabelResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "A label used to scope packs. kind=dynamic runs sql on each host and membership is the hosts where it returns rows. kind=manual lists serials or device ids.",
		Attributes: map[string]schema.Attribute{
			"id":          schema.StringAttribute{Computed: true, PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}},
			"name":        schema.StringAttribute{Required: true},
			"description": schema.StringAttribute{Optional: true, Computed: true, Default: stringdefault.StaticString("")},
			"kind":        schema.StringAttribute{Required: true, Description: "dynamic or manual."},
			"sql":         schema.StringAttribute{Optional: true, Computed: true, Default: stringdefault.StaticString(""), Description: "Required for dynamic labels."},
			"platform":    schema.StringAttribute{Optional: true, Computed: true, Default: stringdefault.StaticString("")},
			"serials":     schema.ListAttribute{ElementType: types.StringType, Optional: true, Computed: true, Default: listdefault.StaticValue(emptyList())},
			"device_ids":  schema.ListAttribute{ElementType: types.StringType, Optional: true, Computed: true, Default: listdefault.StaticValue(emptyList())},
			"managed_by":  schema.StringAttribute{Optional: true, Computed: true, Default: stringdefault.StaticString("terraform")},
		},
	}
}

func (m osqueryLabelModel) api(ctx context.Context) (osqueryLabelAPI, diag.Diagnostics) {
	var diags diag.Diagnostics
	api := osqueryLabelAPI{
		Name: m.Name.ValueString(), Description: m.Description.ValueString(), Kind: m.Kind.ValueString(),
		SQL: m.SQL.ValueString(), Platform: m.Platform.ValueString(), ManagedBy: m.ManagedBy.ValueString(),
	}
	var d diag.Diagnostics
	if api.Serials, d = stringsFromList(ctx, m.Serials); d.HasError() {
		diags.Append(d...)
	}
	if api.DeviceIDs, d = stringsFromList(ctx, m.DeviceIDs); d.HasError() {
		diags.Append(d...)
	}
	return api, diags
}

func modelOsqueryLabel(ctx context.Context, in osqueryLabelAPI) (osqueryLabelModel, diag.Diagnostics) {
	var diags diag.Diagnostics
	m := osqueryLabelModel{
		ID: types.StringValue(in.ID), Name: types.StringValue(in.Name), Description: types.StringValue(in.Description),
		Kind: types.StringValue(in.Kind), SQL: types.StringValue(in.SQL), Platform: types.StringValue(in.Platform),
		ManagedBy: types.StringValue(in.ManagedBy),
	}
	var d diag.Diagnostics
	if m.Serials, d = listOfStrings(ctx, in.Serials); d.HasError() {
		diags.Append(d...)
	}
	if m.DeviceIDs, d = listOfStrings(ctx, in.DeviceIDs); d.HasError() {
		diags.Append(d...)
	}
	return m, diags
}

func (r *osqueryLabelResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan osqueryLabelModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	body, diags := plan.api(ctx)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	out, err := r.client.CreateOsqueryLabel(ctx, body)
	if err != nil {
		resp.Diagnostics.AddError("create osquery label", err.Error())
		return
	}
	model, diags := modelOsqueryLabel(ctx, out)
	resp.Diagnostics.Append(diags...)
	resp.Diagnostics.Append(resp.State.Set(ctx, model)...)
}
func (r *osqueryLabelResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state osqueryLabelModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	out, err := r.client.GetOsqueryLabel(ctx, state.ID.ValueString())
	if notFound(err) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("read osquery label", err.Error())
		return
	}
	model, diags := modelOsqueryLabel(ctx, out)
	resp.Diagnostics.Append(diags...)
	resp.Diagnostics.Append(resp.State.Set(ctx, model)...)
}
func (r *osqueryLabelResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan osqueryLabelModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	body, diags := plan.api(ctx)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	out, err := r.client.UpdateOsqueryLabel(ctx, plan.ID.ValueString(), body)
	if err != nil {
		resp.Diagnostics.AddError("update osquery label", err.Error())
		return
	}
	model, diags := modelOsqueryLabel(ctx, out)
	resp.Diagnostics.Append(diags...)
	resp.Diagnostics.Append(resp.State.Set(ctx, model)...)
}
func (r *osqueryLabelResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state osqueryLabelModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.DeleteOsqueryLabel(ctx, state.ID.ValueString()); err != nil && !notFound(err) {
		resp.Diagnostics.AddError("delete osquery label", err.Error())
	}
}
func (r *osqueryLabelResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

type enrollSecretResource struct{ client *Client }

func newEnrollSecretResource() resource.Resource { return &enrollSecretResource{} }

func (r *enrollSecretResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_osquery_enroll_secret"
}
func (r *enrollSecretResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.client = configureClient(req, resp)
}

type enrollSecretModel struct {
	ID                types.String `tfsdk:"id"`
	Name              types.String `tfsdk:"name"`
	Secret            types.String `tfsdk:"secret"`
	Enabled           types.Bool   `tfsdk:"enabled"`
	ManagedBy         types.String `tfsdk:"managed_by"`
	SecretFingerprint types.String `tfsdk:"secret_fingerprint"`
}

func (r *enrollSecretResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "An osquery enroll secret. The API stores only a hash. Keep more than one enabled secret while rotating so already-issued instructions and new agents overlap. Enrolled nodes keep their node key until it is invalidated. secret is write-only: it is sent on create and update, never stored in state, and never returned by the API. Import leaves secret_fingerprint null, so import does not plan an update.",
		Attributes: map[string]schema.Attribute{
			"id":                 schema.StringAttribute{Computed: true, PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}},
			"name":               schema.StringAttribute{Required: true},
			"secret":             schema.StringAttribute{Required: true, Sensitive: true, WriteOnly: true, Description: "Write-only. The API stores a hash and never returns the value. Changing it after create rotates the hash. Import does not plan an update."},
			"enabled":            schema.BoolAttribute{Optional: true, Computed: true, Default: booldefault.StaticBool(true)},
			"managed_by":         schema.StringAttribute{Optional: true, Computed: true, Default: stringdefault.StaticString("terraform")},
			"secret_fingerprint": schema.StringAttribute{Computed: true, PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}, Description: "SHA-256 of the configured secret. Null after import."},
		},
	}
}

func modelEnrollSecret(in enrollSecretAPI, fingerprint types.String) enrollSecretModel {
	return enrollSecretModel{
		ID: types.StringValue(in.ID), Name: types.StringValue(in.Name),
		Enabled: types.BoolValue(in.Enabled), ManagedBy: types.StringValue(in.ManagedBy),
		SecretFingerprint: fingerprint,
	}
}

func (r *enrollSecretResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan, cfg enrollSecretModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}
	secret := configuredSecret(cfg.Secret)
	out, err := r.client.CreateEnrollSecret(ctx, enrollSecretAPI{Name: plan.Name.ValueString(), Secret: secret, Enabled: plan.Enabled.ValueBool(), ManagedBy: plan.ManagedBy.ValueString()})
	if err != nil {
		resp.Diagnostics.AddError("create enroll secret", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, modelEnrollSecret(out, types.StringValue(credentialFingerprint(secret))))...)
}
func (r *enrollSecretResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state enrollSecretModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	out, err := r.client.GetEnrollSecret(ctx, state.ID.ValueString())
	if notFound(err) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("read enroll secret", err.Error())
		return
	}
	fingerprint := types.StringNull()
	if !state.SecretFingerprint.IsNull() && !state.SecretFingerprint.IsUnknown() {
		fingerprint = state.SecretFingerprint
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, modelEnrollSecret(out, fingerprint))...)
}
func (r *enrollSecretResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, cfg enrollSecretModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}
	secret := configuredSecret(cfg.Secret)
	out, err := r.client.UpdateEnrollSecret(ctx, plan.ID.ValueString(), enrollSecretAPI{Name: plan.Name.ValueString(), Secret: secret, Enabled: plan.Enabled.ValueBool(), ManagedBy: plan.ManagedBy.ValueString()})
	if err != nil {
		resp.Diagnostics.AddError("update enroll secret", err.Error())
		return
	}
	fingerprint := plan.SecretFingerprint
	if fingerprint.IsNull() || fingerprint.IsUnknown() {
		fingerprint = types.StringValue(credentialFingerprint(secret))
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, modelEnrollSecret(out, fingerprint))...)
}
func (r *enrollSecretResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state enrollSecretModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.DeleteEnrollSecret(ctx, state.ID.ValueString()); err != nil && !notFound(err) {
		resp.Diagnostics.AddError("delete enroll secret", err.Error())
	}
}
func (r *enrollSecretResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

func (r *enrollSecretResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	if req.Plan.Raw.IsNull() {
		return
	}
	var cfg, plan enrollSecretModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	plan.Secret = types.StringNull()
	prior := types.StringNull()
	if !req.State.Raw.IsNull() {
		var state enrollSecretModel
		resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
		if resp.Diagnostics.HasError() {
			return
		}
		prior = state.SecretFingerprint
	}
	plan.SecretFingerprint = nextFingerprint(req.State.Raw.IsNull(), prior, []types.String{cfg.Secret})
	resp.Diagnostics.Append(resp.Plan.Set(ctx, plan)...)
}
