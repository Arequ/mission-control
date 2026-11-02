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

type recipeRepoResource struct{ client *Client }

func newRecipeRepoResource() resource.Resource { return &recipeRepoResource{} }

func (r *recipeRepoResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_recipe_repo"
}
func (r *recipeRepoResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.client = configureClient(req, resp)
}

type recipeRepoModel struct {
	ID        types.String `tfsdk:"id"`
	Name      types.String `tfsdk:"name"`
	URL       types.String `tfsdk:"url"`
	Ref       types.String `tfsdk:"ref"`
	ManagedBy types.String `tfsdk:"managed_by"`
}

func recipeRepoSchema() schema.Schema {
	return schema.Schema{
		Description: "A git repository of AutoPkg recipes. The runner clones it when MC_SYNC_REPOS is enabled.",
		Attributes: map[string]schema.Attribute{
			"id":         schema.StringAttribute{Computed: true, PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}},
			"name":       schema.StringAttribute{Required: true, Description: "Short name, unique in Mission Control."},
			"url":        schema.StringAttribute{Required: true, Description: "Git URL."},
			"ref":        schema.StringAttribute{Optional: true, Computed: true, Default: stringdefault.StaticString("main"), Description: "Branch or tag."},
			"managed_by": schema.StringAttribute{Optional: true, Computed: true, Default: stringdefault.StaticString("terraform")},
		},
	}
}

func (r *recipeRepoResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = recipeRepoSchema()
}

func (m recipeRepoModel) api() recipeRepoAPI {
	return recipeRepoAPI{Name: m.Name.ValueString(), URL: m.URL.ValueString(), Ref: m.Ref.ValueString(), ManagedBy: m.ManagedBy.ValueString()}
}

func modelRepo(in recipeRepoAPI) recipeRepoModel {
	return recipeRepoModel{
		ID: types.StringValue(in.ID), Name: types.StringValue(in.Name), URL: types.StringValue(in.URL),
		Ref: types.StringValue(in.Ref), ManagedBy: types.StringValue(in.ManagedBy),
	}
}

func (r *recipeRepoResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan recipeRepoModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	out, err := r.client.CreateRecipeRepo(ctx, plan.api())
	if err != nil {
		resp.Diagnostics.AddError("create recipe repo", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, modelRepo(out))...)
}
func (r *recipeRepoResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state recipeRepoModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	out, err := r.client.GetRecipeRepo(ctx, state.ID.ValueString())
	if notFound(err) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("read recipe repo", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, modelRepo(out))...)
}
func (r *recipeRepoResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan recipeRepoModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	out, err := r.client.UpdateRecipeRepo(ctx, plan.ID.ValueString(), plan.api())
	if err != nil {
		resp.Diagnostics.AddError("update recipe repo", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, modelRepo(out))...)
}
func (r *recipeRepoResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state recipeRepoModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.DeleteRecipeRepo(ctx, state.ID.ValueString()); err != nil && !notFound(err) {
		resp.Diagnostics.AddError("delete recipe repo", err.Error())
	}
}
func (r *recipeRepoResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
