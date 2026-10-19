package provider

import (
	"context"
	"encoding/json"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/listdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type recipeResource struct{ client *Client }

func newRecipeResource() resource.Resource { return &recipeResource{} }

func (r *recipeResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_recipe"
}
func (r *recipeResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.client = configureClient(req, resp)
}

type recipeModel struct {
	ID           types.String `tfsdk:"id"`
	Identifier   types.String `tfsdk:"identifier"`
	Name         types.String `tfsdk:"name"`
	RepoID       types.String `tfsdk:"repo_id"`
	Enabled      types.Bool   `tfsdk:"enabled"`
	Override     types.String `tfsdk:"override"`
	TrustInfo    types.String `tfsdk:"trust_info"`
	RunnerPoolID types.String `tfsdk:"runner_pool_id"`
	Labels       types.List   `tfsdk:"labels"`
	ManagedBy    types.String `tfsdk:"managed_by"`
}

func (r *recipeResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "An AutoPkg recipe override: identifier, override contents, trust info, and whether it is enabled.",
		Attributes: map[string]schema.Attribute{
			"id":             schema.StringAttribute{Computed: true, PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}},
			"identifier":     schema.StringAttribute{Required: true, Description: "AutoPkg identifier, for example local.munki.Firefox."},
			"name":           schema.StringAttribute{Required: true},
			"repo_id":        schema.StringAttribute{Optional: true, Description: "missioncontrol_recipe_repo id."},
			"enabled":        schema.BoolAttribute{Optional: true, Computed: true, Default: booldefault.StaticBool(true)},
			"override":       schema.StringAttribute{Required: true, Description: "Recipe override plist or YAML."},
			"trust_info":     schema.StringAttribute{Optional: true, Computed: true, Default: stringdefault.StaticString("{}"), Description: "JSON trust info passed to autopkg verify-trust-info."},
			"runner_pool_id": schema.StringAttribute{Optional: true},
			"labels": schema.ListAttribute{
				ElementType: types.StringType, Optional: true, Computed: true,
				Default:     listdefault.StaticValue(emptyList()),
				Description: "Runner labels required to lease this recipe. Empty matches every runner.",
			},
			"managed_by": schema.StringAttribute{Optional: true, Computed: true, Default: stringdefault.StaticString("terraform")},
		},
	}
}

func (m recipeModel) api(ctx context.Context) (recipeAPI, diag.Diagnostics) {
	var diags diag.Diagnostics
	labels, ld := stringsFromList(ctx, m.Labels)
	diags.Append(ld...)
	if diags.HasError() {
		return recipeAPI{}, diags
	}
	raw, err := rawJSON(m.TrustInfo.ValueString())
	if err != nil {
		diags.AddError("trust_info", "trust_info must be JSON: "+err.Error())
		return recipeAPI{}, diags
	}
	return recipeAPI{
		Identifier: m.Identifier.ValueString(), Name: m.Name.ValueString(),
		RepoID: optString(m.RepoID), Enabled: m.Enabled.ValueBool(), Override: m.Override.ValueString(),
		TrustInfo: raw, RunnerPoolID: optString(m.RunnerPoolID), Labels: labels, ManagedBy: m.ManagedBy.ValueString(),
	}, diags
}

func modelRecipe(ctx context.Context, in recipeAPI) (recipeModel, diag.Diagnostics) {
	var diags diag.Diagnostics
	labels, ld := listOfStrings(ctx, in.Labels)
	diags.Append(ld...)
	trust := "{}"
	if len(in.TrustInfo) > 0 {
		var v any
		if err := json.Unmarshal(in.TrustInfo, &v); err != nil {
			diags.AddError("trust_info", err.Error())
			return recipeModel{}, diags
		}
		b, err := json.Marshal(v)
		if err != nil {
			diags.AddError("trust_info", err.Error())
			return recipeModel{}, diags
		}
		trust = string(b)
	}
	return recipeModel{
		ID: types.StringValue(in.ID), Identifier: types.StringValue(in.Identifier), Name: types.StringValue(in.Name),
		RepoID: stringValue(in.RepoID), Enabled: types.BoolValue(in.Enabled), Override: types.StringValue(in.Override),
		TrustInfo: types.StringValue(trust), RunnerPoolID: stringValue(in.RunnerPoolID), Labels: labels,
		ManagedBy: types.StringValue(in.ManagedBy),
	}, diags
}

func (r *recipeResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan recipeModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	body, diags := plan.api(ctx)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	out, err := r.client.CreateRecipe(ctx, body)
	if err != nil {
		resp.Diagnostics.AddError("create recipe", err.Error())
		return
	}
	model, diags := modelRecipe(ctx, out)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, model)...)
}

func (r *recipeResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state recipeModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	out, err := r.client.GetRecipe(ctx, state.ID.ValueString())
	if notFound(err) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("read recipe", err.Error())
		return
	}
	model, diags := modelRecipe(ctx, out)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, model)...)
}

func (r *recipeResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan recipeModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	body, diags := plan.api(ctx)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	out, err := r.client.UpdateRecipe(ctx, plan.ID.ValueString(), body)
	if err != nil {
		resp.Diagnostics.AddError("update recipe", err.Error())
		return
	}
	model, diags := modelRecipe(ctx, out)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, model)...)
}

func (r *recipeResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state recipeModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.DeleteRecipe(ctx, state.ID.ValueString()); err != nil && !notFound(err) {
		resp.Diagnostics.AddError("delete recipe", err.Error())
	}
}

func (r *recipeResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
