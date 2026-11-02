package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type pipelineResource struct{ client *Client }

func newPipelineResource() resource.Resource { return &pipelineResource{} }

func (r *pipelineResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_pipeline_settings"
}
func (r *pipelineResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.client = configureClient(req, resp)
}

type pipelineModel struct {
	ID                   types.String `tfsdk:"id"`
	MaxConcurrency       types.Int64  `tfsdk:"max_concurrency"`
	PerRunnerParallelism types.Int64  `tfsdk:"per_runner_parallelism"`
	TimeoutSeconds       types.Int64  `tfsdk:"timeout_seconds"`
	MaxRetries           types.Int64  `tfsdk:"max_retries"`
	LeaseSeconds         types.Int64  `tfsdk:"lease_seconds"`
	ManagedBy            types.String `tfsdk:"managed_by"`
}

func (r *pipelineResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Fleet-wide AutoPkg pipeline limits. There is a single settings object; destroying it restores server defaults.",
		Attributes: map[string]schema.Attribute{
			"id":                     schema.StringAttribute{Computed: true, PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}},
			"max_concurrency":        schema.Int64Attribute{Required: true, Description: "How many jobs may run at once across the fleet."},
			"per_runner_parallelism": schema.Int64Attribute{Required: true, Description: "How many jobs one runner may hold at once."},
			"timeout_seconds":        schema.Int64Attribute{Required: true},
			"max_retries":            schema.Int64Attribute{Required: true, Description: "Extra attempts after a runner error or a dead lease."},
			"lease_seconds":          schema.Int64Attribute{Required: true, Description: "A runner must renew before this elapses or the job is requeued."},
			"managed_by":             schema.StringAttribute{Optional: true, Computed: true, Default: stringdefault.StaticString("terraform")},
		},
	}
}

func (m pipelineModel) api() pipelineAPI {
	return pipelineAPI{
		MaxConcurrency: int(m.MaxConcurrency.ValueInt64()), PerRunnerParallelism: int(m.PerRunnerParallelism.ValueInt64()),
		TimeoutSeconds: int(m.TimeoutSeconds.ValueInt64()), MaxRetries: int(m.MaxRetries.ValueInt64()),
		LeaseSeconds: int(m.LeaseSeconds.ValueInt64()), ManagedBy: m.ManagedBy.ValueString(),
	}
}
func modelPipeline(in pipelineAPI) pipelineModel {
	return pipelineModel{
		ID: types.StringValue("default"), MaxConcurrency: types.Int64Value(int64(in.MaxConcurrency)),
		PerRunnerParallelism: types.Int64Value(int64(in.PerRunnerParallelism)),
		TimeoutSeconds:       types.Int64Value(int64(in.TimeoutSeconds)), MaxRetries: types.Int64Value(int64(in.MaxRetries)),
		LeaseSeconds: types.Int64Value(int64(in.LeaseSeconds)), ManagedBy: types.StringValue(in.ManagedBy),
	}
}

func (r *pipelineResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan pipelineModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	out, err := r.client.UpdatePipeline(ctx, plan.api())
	if err != nil {
		resp.Diagnostics.AddError("update pipeline settings", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, modelPipeline(out))...)
}
func (r *pipelineResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	out, err := r.client.GetPipeline(ctx)
	if err != nil {
		resp.Diagnostics.AddError("read pipeline settings", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, modelPipeline(out))...)
}
func (r *pipelineResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan pipelineModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	out, err := r.client.UpdatePipeline(ctx, plan.api())
	if err != nil {
		resp.Diagnostics.AddError("update pipeline settings", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, modelPipeline(out))...)
}
func (r *pipelineResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	if err := r.client.ResetPipeline(ctx); err != nil {
		resp.Diagnostics.AddError("reset pipeline settings", err.Error())
	}
}
func (r *pipelineResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
