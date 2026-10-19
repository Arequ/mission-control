package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/attr"
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
	ConditionalItem   types.List   `tfsdk:"conditional_item"`
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
		Blocks: map[string]schema.Block{
			"conditional_item": schema.ListNestedBlock{
				Description: "Munki conditional_items. Omitted when empty so a manifest without conditions does not drift.",
				NestedObject: schema.NestedBlockObject{Attributes: map[string]schema.Attribute{
					"condition":          schema.StringAttribute{Required: true},
					"managed_installs":   listAttr("Installs applied when the condition is true."),
					"optional_installs":  listAttr(""),
					"managed_uninstalls": listAttr(""),
					"included_manifests": listAttr(""),
				}},
			},
		},
	}
}

type conditionalItemModel struct {
	Condition         types.String `tfsdk:"condition"`
	ManagedInstalls   types.List   `tfsdk:"managed_installs"`
	OptionalInstalls  types.List   `tfsdk:"optional_installs"`
	ManagedUninstalls types.List   `tfsdk:"managed_uninstalls"`
	IncludedManifests types.List   `tfsdk:"included_manifests"`
}

func conditionalItemTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"condition":          types.StringType,
		"managed_installs":   types.ListType{ElemType: types.StringType},
		"optional_installs":  types.ListType{ElemType: types.StringType},
		"managed_uninstalls": types.ListType{ElemType: types.StringType},
		"included_manifests": types.ListType{ElemType: types.StringType},
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
	items, d := conditionalModels(ctx, m.ConditionalItem)
	diags.Append(d...)
	api.ConditionalItems = make([]conditionalItemAPI, 0, len(items))
	for _, item := range items {
		row := conditionalItemAPI{Condition: item.Condition.ValueString()}
		if row.ManagedInstalls, d = stringsFromList(ctx, item.ManagedInstalls); d.HasError() {
			diags.Append(d...)
		}
		if row.OptionalInstalls, d = stringsFromList(ctx, item.OptionalInstalls); d.HasError() {
			diags.Append(d...)
		}
		if row.ManagedUninstalls, d = stringsFromList(ctx, item.ManagedUninstalls); d.HasError() {
			diags.Append(d...)
		}
		if row.IncludedManifests, d = stringsFromList(ctx, item.IncludedManifests); d.HasError() {
			diags.Append(d...)
		}
		api.ConditionalItems = append(api.ConditionalItems, row)
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
	if m.ConditionalItem, d = conditionalList(ctx, in.ConditionalItems); d.HasError() {
		diags.Append(d...)
	}
	return m, diags
}

func conditionalModels(ctx context.Context, list types.List) ([]conditionalItemModel, diag.Diagnostics) {
	if list.IsNull() || list.IsUnknown() {
		return nil, nil
	}
	var items []conditionalItemModel
	diags := list.ElementsAs(ctx, &items, false)
	return items, diags
}

func conditionalList(ctx context.Context, in []conditionalItemAPI) (types.List, diag.Diagnostics) {
	if len(in) == 0 {
		return types.ListNull(types.ObjectType{AttrTypes: conditionalItemTypes()}), nil
	}
	objs := make([]attr.Value, 0, len(in))
	var diags diag.Diagnostics
	for _, item := range in {
		managed, d := listOfStrings(ctx, item.ManagedInstalls)
		diags.Append(d...)
		optional, d := listOfStrings(ctx, item.OptionalInstalls)
		diags.Append(d...)
		uninstalls, d := listOfStrings(ctx, item.ManagedUninstalls)
		diags.Append(d...)
		included, d := listOfStrings(ctx, item.IncludedManifests)
		diags.Append(d...)
		obj, d := types.ObjectValue(conditionalItemTypes(), map[string]attr.Value{
			"condition":          types.StringValue(item.Condition),
			"managed_installs":   managed,
			"optional_installs":  optional,
			"managed_uninstalls": uninstalls,
			"included_manifests": included,
		})
		diags.Append(d...)
		objs = append(objs, obj)
	}
	list, d := types.ListValue(types.ObjectType{AttrTypes: conditionalItemTypes()}, objs)
	diags.Append(d...)
	return list, diags
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
