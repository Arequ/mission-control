package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type scheduleResource struct{ client *Client }

func newScheduleResource() resource.Resource { return &scheduleResource{} }

func (r *scheduleResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_schedule"
}
func (r *scheduleResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.client = configureClient(req, resp)
}

type scheduleModel struct {
	ID        types.String `tfsdk:"id"`
	Name      types.String `tfsdk:"name"`
	RecipeID  types.String `tfsdk:"recipe_id"`
	Cron      types.String `tfsdk:"cron"`
	Enabled   types.Bool   `tfsdk:"enabled"`
	ManagedBy types.String `tfsdk:"managed_by"`
}

func (r *scheduleResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Five-field cron schedule for a recipe. The first run waits until the next cron instant; use the run-now API to enqueue immediately.",
		Attributes: map[string]schema.Attribute{
			"id":         schema.StringAttribute{Computed: true, PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}},
			"name":       schema.StringAttribute{Required: true},
			"recipe_id":  schema.StringAttribute{Required: true},
			"cron":       schema.StringAttribute{Required: true, Description: "minute hour day-of-month month day-of-week"},
			"enabled":    schema.BoolAttribute{Optional: true, Computed: true, Default: booldefault.StaticBool(true)},
			"managed_by": schema.StringAttribute{Optional: true, Computed: true, Default: stringdefault.StaticString("terraform")},
		},
	}
}

func (m scheduleModel) api() scheduleAPI {
	return scheduleAPI{Name: m.Name.ValueString(), RecipeID: m.RecipeID.ValueString(), Cron: m.Cron.ValueString(), Enabled: m.Enabled.ValueBool(), ManagedBy: m.ManagedBy.ValueString()}
}
func modelSchedule(in scheduleAPI) scheduleModel {
	return scheduleModel{
		ID: types.StringValue(in.ID), Name: types.StringValue(in.Name), RecipeID: types.StringValue(in.RecipeID),
		Cron: types.StringValue(in.Cron), Enabled: types.BoolValue(in.Enabled), ManagedBy: types.StringValue(in.ManagedBy),
	}
}

func (r *scheduleResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan scheduleModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	out, err := r.client.CreateSchedule(ctx, plan.api())
	if err != nil {
		resp.Diagnostics.AddError("create schedule", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, modelSchedule(out))...)
}
func (r *scheduleResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state scheduleModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	out, err := r.client.GetSchedule(ctx, state.ID.ValueString())
	if notFound(err) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("read schedule", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, modelSchedule(out))...)
}
func (r *scheduleResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan scheduleModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	out, err := r.client.UpdateSchedule(ctx, plan.ID.ValueString(), plan.api())
	if err != nil {
		resp.Diagnostics.AddError("update schedule", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, modelSchedule(out))...)
}
func (r *scheduleResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state scheduleModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.DeleteSchedule(ctx, state.ID.ValueString()); err != nil && !notFound(err) {
		resp.Diagnostics.AddError("delete schedule", err.Error())
	}
}
func (r *scheduleResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
