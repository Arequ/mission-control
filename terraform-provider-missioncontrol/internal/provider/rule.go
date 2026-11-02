package provider

import (
	"context"

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

type ruleResource struct{ client *Client }

func newPromotionRuleResource() resource.Resource { return &ruleResource{} }

func (r *ruleResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_promotion_rule"
}
func (r *ruleResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.client = configureClient(req, resp)
}

type ruleModel struct {
	ID          types.String `tfsdk:"id"`
	Name        types.String `tfsdk:"name"`
	FromCatalog types.String `tfsdk:"from_catalog"`
	ToCatalog   types.String `tfsdk:"to_catalog"`
	SoakDays    types.Int64  `tfsdk:"soak_days"`
	ManualHold  types.Bool   `tfsdk:"manual_hold"`
	Enabled     types.Bool   `tfsdk:"enabled"`
	ManagedBy   types.String `tfsdk:"managed_by"`
}

func (r *ruleResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Moves pkginfo from one catalog to another after a soak. manual_hold keeps items until an operator promotes them.",
		Attributes: map[string]schema.Attribute{
			"id":           schema.StringAttribute{Computed: true, PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}},
			"name":         schema.StringAttribute{Required: true},
			"from_catalog": schema.StringAttribute{Required: true},
			"to_catalog":   schema.StringAttribute{Required: true},
			"soak_days":    schema.Int64Attribute{Optional: true, Computed: true, Default: int64default.StaticInt64(7)},
			"manual_hold":  schema.BoolAttribute{Optional: true, Computed: true, Default: booldefault.StaticBool(false)},
			"enabled":      schema.BoolAttribute{Optional: true, Computed: true, Default: booldefault.StaticBool(true)},
			"managed_by":   schema.StringAttribute{Optional: true, Computed: true, Default: stringdefault.StaticString("terraform")},
		},
	}
}

func (m ruleModel) api() ruleAPI {
	return ruleAPI{
		Name: m.Name.ValueString(), FromCatalog: m.FromCatalog.ValueString(), ToCatalog: m.ToCatalog.ValueString(),
		SoakDays: int(m.SoakDays.ValueInt64()), ManualHold: m.ManualHold.ValueBool(), Enabled: m.Enabled.ValueBool(),
		ManagedBy: m.ManagedBy.ValueString(),
	}
}

func modelRule(in ruleAPI) ruleModel {
	return ruleModel{
		ID: types.StringValue(in.ID), Name: types.StringValue(in.Name), FromCatalog: types.StringValue(in.FromCatalog),
		ToCatalog: types.StringValue(in.ToCatalog), SoakDays: types.Int64Value(int64(in.SoakDays)),
		ManualHold: types.BoolValue(in.ManualHold), Enabled: types.BoolValue(in.Enabled), ManagedBy: types.StringValue(in.ManagedBy),
	}
}

func (r *ruleResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan ruleModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	out, err := r.client.CreateRule(ctx, plan.api())
	if err != nil {
		resp.Diagnostics.AddError("create promotion rule", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, modelRule(out))...)
}
func (r *ruleResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state ruleModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	out, err := r.client.GetRule(ctx, state.ID.ValueString())
	if notFound(err) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("read promotion rule", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, modelRule(out))...)
}
func (r *ruleResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan ruleModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	out, err := r.client.UpdateRule(ctx, plan.ID.ValueString(), plan.api())
	if err != nil {
		resp.Diagnostics.AddError("update promotion rule", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, modelRule(out))...)
}
func (r *ruleResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state ruleModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.DeleteRule(ctx, state.ID.ValueString()); err != nil && !notFound(err) {
		resp.Diagnostics.AddError("delete promotion rule", err.Error())
	}
}
func (r *ruleResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
