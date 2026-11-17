package provider

import (
	"context"
	"net/http"
	"sort"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type roleAPI struct {
	ID          string   `json:"id,omitempty"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Permissions []string `json:"permissions"`
	ManagedBy   string   `json:"managed_by,omitempty"`
}

func (c *Client) CreateRole(ctx context.Context, in roleAPI) (roleAPI, error) {
	var out roleAPI
	err := c.do(ctx, http.MethodPost, "/api/v1/sso/roles", in, &out)
	return out, err
}
func (c *Client) GetRole(ctx context.Context, id string) (roleAPI, error) {
	var out roleAPI
	err := c.do(ctx, http.MethodGet, "/api/v1/sso/roles/"+id, nil, &out)
	return out, err
}
func (c *Client) UpdateRole(ctx context.Context, id string, in roleAPI) (roleAPI, error) {
	var out roleAPI
	err := c.do(ctx, http.MethodPut, "/api/v1/sso/roles/"+id, in, &out)
	return out, err
}
func (c *Client) DeleteRole(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodDelete, "/api/v1/sso/roles/"+id, nil, nil)
}

type roleResource struct{ client *Client }

func newRoleResource() resource.Resource { return &roleResource{} }

func (r *roleResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_role"
}
func (r *roleResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.client = configureClient(req, resp)
}

type roleModel struct {
	ID          types.String `tfsdk:"id"`
	Name        types.String `tfsdk:"name"`
	Description types.String `tfsdk:"description"`
	Permissions types.Set    `tfsdk:"permissions"`
	ManagedBy   types.String `tfsdk:"managed_by"`
}

func (r *roleResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "A custom role for missioncontrol_role_binding. Permissions are <area>:<read|write|update>: read views, write creates or triggers, update changes or decides. write or update on an area implies read on it. Areas: audit, config, jobs, keel, logs, munki, osquery, releases, runners, vuln. config:write, config:update, and * cannot be granted. A user gets the union of every role their groups match. Changes apply on the next request.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{Computed: true, PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}},
			"name": schema.StringAttribute{
				Required: true, Description: "Lowercase name bindings refer to, for example it-ops. Changing it replaces the role.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"description": schema.StringAttribute{Optional: true, Computed: true, Default: stringdefault.StaticString("")},
			"permissions": schema.SetAttribute{ElementType: types.StringType, Required: true, Description: "For example [\"munki:read\", \"releases:update\"]."},
			"managed_by":  schema.StringAttribute{Optional: true, Computed: true, Default: stringdefault.StaticString("terraform")},
		},
	}
}

func roleFromPlan(ctx context.Context, plan roleModel) (roleAPI, diag.Diagnostics) {
	var perms []string
	diags := plan.Permissions.ElementsAs(ctx, &perms, false)
	sort.Strings(perms)
	return roleAPI{
		Name: plan.Name.ValueString(), Description: plan.Description.ValueString(),
		Permissions: perms, ManagedBy: plan.ManagedBy.ValueString(),
	}, diags
}

func modelRole(in roleAPI) (roleModel, diag.Diagnostics) {
	elems := make([]attr.Value, 0, len(in.Permissions))
	for _, p := range in.Permissions {
		elems = append(elems, types.StringValue(p))
	}
	set, diags := types.SetValue(types.StringType, elems)
	return roleModel{
		ID: types.StringValue(in.ID), Name: types.StringValue(in.Name), Description: types.StringValue(in.Description),
		Permissions: set, ManagedBy: types.StringValue(in.ManagedBy),
	}, diags
}

func (r *roleResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan roleModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	in, diags := roleFromPlan(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	out, err := r.client.CreateRole(ctx, in)
	if err != nil {
		resp.Diagnostics.AddError("create role", err.Error())
		return
	}
	state, diags := modelRole(out)
	resp.Diagnostics.Append(diags...)
	resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
}

func (r *roleResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state roleModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	out, err := r.client.GetRole(ctx, state.ID.ValueString())
	if notFound(err) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("read role", err.Error())
		return
	}
	next, diags := modelRole(out)
	resp.Diagnostics.Append(diags...)
	resp.Diagnostics.Append(resp.State.Set(ctx, next)...)
}

func (r *roleResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan roleModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	in, diags := roleFromPlan(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	out, err := r.client.UpdateRole(ctx, plan.ID.ValueString(), in)
	if err != nil {
		resp.Diagnostics.AddError("update role", err.Error())
		return
	}
	state, diags := modelRole(out)
	resp.Diagnostics.Append(diags...)
	resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
}

func (r *roleResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state roleModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.DeleteRole(ctx, state.ID.ValueString()); err != nil && !notFound(err) {
		resp.Diagnostics.AddError("delete role", err.Error())
	}
}

func (r *roleResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
