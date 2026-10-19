package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/listdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type manifestResource struct{ client *Client }

func newManifestResource() resource.Resource { return &manifestResource{} }

func (r *manifestResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_manifest"
}
func (r *manifestResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.client = configureClient(req, resp)
}

type manifestModel struct {
	ID                types.String `tfsdk:"id"`
	Name              types.String `tfsdk:"name"`
	Catalogs          types.List   `tfsdk:"catalogs"`
	IncludedManifests types.List   `tfsdk:"included_manifests"`
	ManagedInstalls   types.List   `tfsdk:"managed_installs"`
	OptionalInstalls  types.List   `tfsdk:"optional_installs"`
	ManagedUninstalls types.List   `tfsdk:"managed_uninstalls"`
	ManagedBy         types.String `tfsdk:"managed_by"`
}

func listAttr(desc string) schema.ListAttribute {
	return schema.ListAttribute{
		ElementType: types.StringType, Optional: true, Computed: true,
		Default: listdefault.StaticValue(emptyList()), Description: desc,
	}
}

func (r *manifestResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "A Munki manifest served at /repo/manifests/<name>. Read-only in the UI.",
		Attributes: map[string]schema.Attribute{
			"id":                 schema.StringAttribute{Computed: true, PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}},
			"name":               schema.StringAttribute{Required: true, Description: "Manifest name clients request, for example site_default."},
			"catalogs":           listAttr("Catalogs Munki consults, in order."),
			"included_manifests": listAttr(""),
			"managed_installs":   listAttr(""),
			"optional_installs":  listAttr(""),
			"managed_uninstalls": listAttr(""),
			"managed_by":         schema.StringAttribute{Optional: true, Computed: true, Default: stringdefault.StaticString("terraform")},
		},
	}
}

func (m manifestModel) api(ctx context.Context) (manifestAPI, diag.Diagnostics) {
	var diags diag.Diagnostics
	var api manifestAPI
	var d diag.Diagnostics
	api.Name = m.Name.ValueString()
	api.ManagedBy = m.ManagedBy.ValueString()
	if api.Catalogs, d = stringsFromList(ctx, m.Catalogs); d.HasError() {
		diags.Append(d...)
	}
	if api.IncludedManifests, d = stringsFromList(ctx, m.IncludedManifests); d.HasError() {
		diags.Append(d...)
	}
	if api.ManagedInstalls, d = stringsFromList(ctx, m.ManagedInstalls); d.HasError() {
		diags.Append(d...)
	}
	if api.OptionalInstalls, d = stringsFromList(ctx, m.OptionalInstalls); d.HasError() {
		diags.Append(d...)
	}
	if api.ManagedUninstalls, d = stringsFromList(ctx, m.ManagedUninstalls); d.HasError() {
		diags.Append(d...)
	}
	return api, diags
}

func modelManifest(ctx context.Context, in manifestAPI) (manifestModel, diag.Diagnostics) {
	var diags diag.Diagnostics
	m := manifestModel{ID: types.StringValue(in.ID), Name: types.StringValue(in.Name), ManagedBy: types.StringValue(in.ManagedBy)}
	var d diag.Diagnostics
	if m.Catalogs, d = listOfStrings(ctx, in.Catalogs); d.HasError() {
		diags.Append(d...)
	}
	if m.IncludedManifests, d = listOfStrings(ctx, in.IncludedManifests); d.HasError() {
		diags.Append(d...)
	}
	if m.ManagedInstalls, d = listOfStrings(ctx, in.ManagedInstalls); d.HasError() {
		diags.Append(d...)
	}
	if m.OptionalInstalls, d = listOfStrings(ctx, in.OptionalInstalls); d.HasError() {
		diags.Append(d...)
	}
	if m.ManagedUninstalls, d = listOfStrings(ctx, in.ManagedUninstalls); d.HasError() {
		diags.Append(d...)
	}
	return m, diags
}

func (r *manifestResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan manifestModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	body, diags := plan.api(ctx)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	out, err := r.client.CreateManifest(ctx, body)
	if err != nil {
		resp.Diagnostics.AddError("create manifest", err.Error())
		return
	}
	model, diags := modelManifest(ctx, out)
	resp.Diagnostics.Append(diags...)
	resp.Diagnostics.Append(resp.State.Set(ctx, model)...)
}
func (r *manifestResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state manifestModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	out, err := r.client.GetManifest(ctx, state.ID.ValueString())
	if notFound(err) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("read manifest", err.Error())
		return
	}
	model, diags := modelManifest(ctx, out)
	resp.Diagnostics.Append(diags...)
	resp.Diagnostics.Append(resp.State.Set(ctx, model)...)
}
func (r *manifestResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan manifestModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	body, diags := plan.api(ctx)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	out, err := r.client.UpdateManifest(ctx, plan.ID.ValueString(), body)
	if err != nil {
		resp.Diagnostics.AddError("update manifest", err.Error())
		return
	}
	model, diags := modelManifest(ctx, out)
	resp.Diagnostics.Append(diags...)
	resp.Diagnostics.Append(resp.State.Set(ctx, model)...)
}
func (r *manifestResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state manifestModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.DeleteManifest(ctx, state.ID.ValueString()); err != nil && !notFound(err) {
		resp.Diagnostics.AddError("delete manifest", err.Error())
	}
}
func (r *manifestResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
