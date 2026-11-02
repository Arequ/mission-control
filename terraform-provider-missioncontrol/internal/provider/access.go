package provider

import (
	"context"
	"net/http"

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

type munkiEnrollmentAPI struct {
	ID        string `json:"id,omitempty"`
	Name      string `json:"name"`
	Secret    string `json:"secret,omitempty"`
	Manifest  string `json:"manifest"`
	Enabled   bool   `json:"enabled"`
	ManagedBy string `json:"managed_by,omitempty"`
}

func (c *Client) CreateMunkiEnrollment(ctx context.Context, in munkiEnrollmentAPI) (munkiEnrollmentAPI, error) {
	var out munkiEnrollmentAPI
	err := c.do(ctx, http.MethodPost, "/api/v1/munki/enrollments", in, &out)
	return out, err
}
func (c *Client) GetMunkiEnrollment(ctx context.Context, id string) (munkiEnrollmentAPI, error) {
	var out munkiEnrollmentAPI
	err := c.do(ctx, http.MethodGet, "/api/v1/munki/enrollments/"+id, nil, &out)
	return out, err
}
func (c *Client) UpdateMunkiEnrollment(ctx context.Context, id string, in munkiEnrollmentAPI) (munkiEnrollmentAPI, error) {
	var out munkiEnrollmentAPI
	err := c.do(ctx, http.MethodPut, "/api/v1/munki/enrollments/"+id, in, &out)
	return out, err
}
func (c *Client) DeleteMunkiEnrollment(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodDelete, "/api/v1/munki/enrollments/"+id, nil, nil)
}

type munkiEnrollmentResource struct{ client *Client }

func newMunkiEnrollmentResource() resource.Resource { return &munkiEnrollmentResource{} }

func (r *munkiEnrollmentResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_munki_enrollment"
}
func (r *munkiEnrollmentResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.client = configureClient(req, resp)
}

type munkiEnrollmentModel struct {
	ID                types.String `tfsdk:"id"`
	Name              types.String `tfsdk:"name"`
	Secret            types.String `tfsdk:"secret"`
	Manifest          types.String `tfsdk:"manifest"`
	Enabled           types.Bool   `tfsdk:"enabled"`
	ManagedBy         types.String `tfsdk:"managed_by"`
	SecretFingerprint types.String `tfsdk:"secret_fingerprint"`
}

func (r *munkiEnrollmentResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "A shared Munki client credential. Clients send it as HTTP Basic or a bearer token (AdditionalHttpHeaders). The server can also derive a per-serial token from this secret. secret is write-only and is never returned. The config repository should add munki/clients.tf before a propose link exists for this resource.",
		Attributes: map[string]schema.Attribute{
			"id":                 schema.StringAttribute{Computed: true, PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}},
			"name":               schema.StringAttribute{Required: true},
			"secret":             schema.StringAttribute{Required: true, Sensitive: true, WriteOnly: true, Description: "Write-only shared secret. Empty on update keeps the stored value."},
			"manifest":           schema.StringAttribute{Optional: true, Computed: true, Default: stringdefault.StaticString("site_default"), Description: "Manifest included by a per-serial client manifest."},
			"enabled":            schema.BoolAttribute{Optional: true, Computed: true, Default: booldefault.StaticBool(true)},
			"managed_by":         schema.StringAttribute{Optional: true, Computed: true, Default: stringdefault.StaticString("terraform")},
			"secret_fingerprint": schema.StringAttribute{Computed: true, PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}},
		},
	}
}

func modelMunkiEnrollment(in munkiEnrollmentAPI, fingerprint types.String) munkiEnrollmentModel {
	return munkiEnrollmentModel{
		ID: types.StringValue(in.ID), Name: types.StringValue(in.Name), Manifest: types.StringValue(in.Manifest),
		Enabled: types.BoolValue(in.Enabled), ManagedBy: types.StringValue(in.ManagedBy), SecretFingerprint: fingerprint,
	}
}

func (r *munkiEnrollmentResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan, cfg munkiEnrollmentModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}
	secret := configuredSecret(cfg.Secret)
	out, err := r.client.CreateMunkiEnrollment(ctx, munkiEnrollmentAPI{
		Name: plan.Name.ValueString(), Secret: secret, Manifest: plan.Manifest.ValueString(),
		Enabled: plan.Enabled.ValueBool(), ManagedBy: plan.ManagedBy.ValueString(),
	})
	if err != nil {
		resp.Diagnostics.AddError("create munki enrollment", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, modelMunkiEnrollment(out, types.StringValue(credentialFingerprint(secret))))...)
}

func (r *munkiEnrollmentResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state munkiEnrollmentModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	out, err := r.client.GetMunkiEnrollment(ctx, state.ID.ValueString())
	if notFound(err) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("read munki enrollment", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, modelMunkiEnrollment(out, state.SecretFingerprint))...)
}

func (r *munkiEnrollmentResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, cfg munkiEnrollmentModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}
	secret := configuredSecret(cfg.Secret)
	out, err := r.client.UpdateMunkiEnrollment(ctx, plan.ID.ValueString(), munkiEnrollmentAPI{
		Name: plan.Name.ValueString(), Secret: secret, Manifest: plan.Manifest.ValueString(),
		Enabled: plan.Enabled.ValueBool(), ManagedBy: plan.ManagedBy.ValueString(),
	})
	if err != nil {
		resp.Diagnostics.AddError("update munki enrollment", err.Error())
		return
	}
	fingerprint := plan.SecretFingerprint
	if fingerprint.IsNull() || fingerprint.IsUnknown() {
		fingerprint = types.StringValue(credentialFingerprint(secret))
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, modelMunkiEnrollment(out, fingerprint))...)
}

func (r *munkiEnrollmentResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state munkiEnrollmentModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.DeleteMunkiEnrollment(ctx, state.ID.ValueString()); err != nil && !notFound(err) {
		resp.Diagnostics.AddError("delete munki enrollment", err.Error())
	}
}

func (r *munkiEnrollmentResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

func (r *munkiEnrollmentResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	if req.Plan.Raw.IsNull() {
		return
	}
	var cfg, plan munkiEnrollmentModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	plan.Secret = types.StringNull()
	prior := types.StringNull()
	if !req.State.Raw.IsNull() {
		var state munkiEnrollmentModel
		resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
		if resp.Diagnostics.HasError() {
			return
		}
		prior = state.SecretFingerprint
	}
	plan.SecretFingerprint = nextFingerprint(req.State.Raw.IsNull(), prior, []types.String{cfg.Secret})
	resp.Diagnostics.Append(resp.Plan.Set(ctx, plan)...)
}

type munkiClientAPI struct {
	ID           string `json:"id,omitempty"`
	Serial       string `json:"serial"`
	EnrollmentID string `json:"enrollment_id"`
	Token        string `json:"token,omitempty"`
	Manifest     string `json:"manifest"`
	Enabled      bool   `json:"enabled"`
	ManagedBy    string `json:"managed_by,omitempty"`
}

func (c *Client) CreateMunkiClient(ctx context.Context, in munkiClientAPI) (munkiClientAPI, error) {
	var out munkiClientAPI
	err := c.do(ctx, http.MethodPost, "/api/v1/munki/clients", in, &out)
	return out, err
}
func (c *Client) GetMunkiClient(ctx context.Context, id string) (munkiClientAPI, error) {
	var out munkiClientAPI
	err := c.do(ctx, http.MethodGet, "/api/v1/munki/clients/"+id, nil, &out)
	return out, err
}
func (c *Client) UpdateMunkiClient(ctx context.Context, id string, in munkiClientAPI) (munkiClientAPI, error) {
	var out munkiClientAPI
	err := c.do(ctx, http.MethodPut, "/api/v1/munki/clients/"+id, in, &out)
	return out, err
}
func (c *Client) DeleteMunkiClient(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodDelete, "/api/v1/munki/clients/"+id, nil, nil)
}

type munkiClientResource struct{ client *Client }

func newMunkiClientResource() resource.Resource { return &munkiClientResource{} }

func (r *munkiClientResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_munki_client"
}
func (r *munkiClientResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.client = configureClient(req, resp)
}

type munkiClientModel struct {
	ID               types.String `tfsdk:"id"`
	Serial           types.String `tfsdk:"serial"`
	EnrollmentID     types.String `tfsdk:"enrollment_id"`
	Token            types.String `tfsdk:"token"`
	Manifest         types.String `tfsdk:"manifest"`
	Enabled          types.Bool   `tfsdk:"enabled"`
	ManagedBy        types.String `tfsdk:"managed_by"`
	TokenFingerprint types.String `tfsdk:"token_fingerprint"`
}

func (r *munkiClientResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Binds one hardware serial to a manifest. token is an optional write-only per-device secret. Leave it empty to authenticate with the enrollment secret or the enrollment-derived token.",
		Attributes: map[string]schema.Attribute{
			"id":                schema.StringAttribute{Computed: true, PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}},
			"serial":            schema.StringAttribute{Required: true},
			"enrollment_id":     schema.StringAttribute{Required: true},
			"token":             schema.StringAttribute{Optional: true, Sensitive: true, WriteOnly: true, Description: "Optional write-only per-device token. Empty keeps the stored hash."},
			"manifest":          schema.StringAttribute{Optional: true, Computed: true, Default: stringdefault.StaticString(""), Description: "Overrides the enrollment manifest for this serial."},
			"enabled":           schema.BoolAttribute{Optional: true, Computed: true, Default: booldefault.StaticBool(true)},
			"managed_by":        schema.StringAttribute{Optional: true, Computed: true, Default: stringdefault.StaticString("terraform")},
			"token_fingerprint": schema.StringAttribute{Computed: true, PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}},
		},
	}
}

func modelMunkiClient(in munkiClientAPI, fingerprint types.String) munkiClientModel {
	return munkiClientModel{
		ID: types.StringValue(in.ID), Serial: types.StringValue(in.Serial), EnrollmentID: types.StringValue(in.EnrollmentID),
		Manifest: types.StringValue(in.Manifest), Enabled: types.BoolValue(in.Enabled), ManagedBy: types.StringValue(in.ManagedBy),
		TokenFingerprint: fingerprint,
	}
}

func (r *munkiClientResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan, cfg munkiClientModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}
	token := configuredSecret(cfg.Token)
	out, err := r.client.CreateMunkiClient(ctx, munkiClientAPI{
		Serial: plan.Serial.ValueString(), EnrollmentID: plan.EnrollmentID.ValueString(), Token: token,
		Manifest: plan.Manifest.ValueString(), Enabled: plan.Enabled.ValueBool(), ManagedBy: plan.ManagedBy.ValueString(),
	})
	if err != nil {
		resp.Diagnostics.AddError("create munki client", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, modelMunkiClient(out, plan.TokenFingerprint))...)
}

func (r *munkiClientResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state munkiClientModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	out, err := r.client.GetMunkiClient(ctx, state.ID.ValueString())
	if notFound(err) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("read munki client", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, modelMunkiClient(out, state.TokenFingerprint))...)
}

func (r *munkiClientResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, cfg munkiClientModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}
	out, err := r.client.UpdateMunkiClient(ctx, plan.ID.ValueString(), munkiClientAPI{
		Serial: plan.Serial.ValueString(), EnrollmentID: plan.EnrollmentID.ValueString(), Token: configuredSecret(cfg.Token),
		Manifest: plan.Manifest.ValueString(), Enabled: plan.Enabled.ValueBool(), ManagedBy: plan.ManagedBy.ValueString(),
	})
	if err != nil {
		resp.Diagnostics.AddError("update munki client", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, modelMunkiClient(out, plan.TokenFingerprint))...)
}

func (r *munkiClientResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state munkiClientModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.DeleteMunkiClient(ctx, state.ID.ValueString()); err != nil && !notFound(err) {
		resp.Diagnostics.AddError("delete munki client", err.Error())
	}
}
func (r *munkiClientResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
func (r *munkiClientResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	if req.Plan.Raw.IsNull() {
		return
	}
	var cfg, plan munkiClientModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	plan.Token = types.StringNull()
	prior := types.StringNull()
	if !req.State.Raw.IsNull() {
		var state munkiClientModel
		resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
		if resp.Diagnostics.HasError() {
			return
		}
		prior = state.TokenFingerprint
	}
	plan.TokenFingerprint = nextFingerprint(req.State.Raw.IsNull(), prior, []types.String{cfg.Token})
	resp.Diagnostics.Append(resp.Plan.Set(ctx, plan)...)
}

type ssoProviderAPI struct {
	ID             string   `json:"id,omitempty"`
	Name           string   `json:"name"`
	Issuer         string   `json:"issuer"`
	ClientID       string   `json:"client_id"`
	ClientSecret   string   `json:"client_secret,omitempty"`
	AllowedDomains []string `json:"allowed_domains"`
	GroupClaim     string   `json:"group_claim"`
	Enabled        bool     `json:"enabled"`
	ManagedBy      string   `json:"managed_by,omitempty"`
}

func (c *Client) CreateSSOProvider(ctx context.Context, in ssoProviderAPI) (ssoProviderAPI, error) {
	var out ssoProviderAPI
	err := c.do(ctx, http.MethodPost, "/api/v1/sso/config", in, &out)
	return out, err
}
func (c *Client) GetSSOProvider(ctx context.Context, id string) (ssoProviderAPI, error) {
	var out ssoProviderAPI
	err := c.do(ctx, http.MethodGet, "/api/v1/sso/config/"+id, nil, &out)
	return out, err
}
func (c *Client) UpdateSSOProvider(ctx context.Context, id string, in ssoProviderAPI) (ssoProviderAPI, error) {
	var out ssoProviderAPI
	err := c.do(ctx, http.MethodPut, "/api/v1/sso/config/"+id, in, &out)
	return out, err
}
func (c *Client) DeleteSSOProvider(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodDelete, "/api/v1/sso/config/"+id, nil, nil)
}

type ssoProviderResource struct{ client *Client }

func newSSOProviderResource() resource.Resource { return &ssoProviderResource{} }

func (r *ssoProviderResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_sso_provider"
}
func (r *ssoProviderResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.client = configureClient(req, resp)
}

type ssoProviderModel struct {
	ID                types.String `tfsdk:"id"`
	Name              types.String `tfsdk:"name"`
	Issuer            types.String `tfsdk:"issuer"`
	ClientID          types.String `tfsdk:"client_id"`
	ClientSecret      types.String `tfsdk:"client_secret"`
	AllowedDomains    types.List   `tfsdk:"allowed_domains"`
	GroupClaim        types.String `tfsdk:"group_claim"`
	Enabled           types.Bool   `tfsdk:"enabled"`
	ManagedBy         types.String `tfsdk:"managed_by"`
	SecretFingerprint types.String `tfsdk:"secret_fingerprint"`
}

func (r *ssoProviderResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "An OIDC provider for the web UI (authorization code and PKCE). client_secret is write-only. API tokens keep working for Terraform. The config repository should add access/sso.tf before a propose link exists for this resource. SAML is not supported.",
		Attributes: map[string]schema.Attribute{
			"id":                 schema.StringAttribute{Computed: true, PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}},
			"name":               schema.StringAttribute{Required: true},
			"issuer":             schema.StringAttribute{Required: true, Description: "OIDC issuer URL. Okta, Entra ID, Google, and Dex all publish discovery here."},
			"client_id":          schema.StringAttribute{Required: true},
			"client_secret":      schema.StringAttribute{Required: true, Sensitive: true, WriteOnly: true, Description: "Write-only. Empty on update keeps the stored value. Never returned by the API."},
			"allowed_domains":    schema.ListAttribute{ElementType: types.StringType, Optional: true, Computed: true, Default: listdefault.StaticValue(emptyList()), Description: "Email domains that may sign in. Empty allows any domain. Google's hd claim must match when it is present."},
			"group_claim":        schema.StringAttribute{Optional: true, Computed: true, Default: stringdefault.StaticString("groups")},
			"enabled":            schema.BoolAttribute{Optional: true, Computed: true, Default: booldefault.StaticBool(true)},
			"managed_by":         schema.StringAttribute{Optional: true, Computed: true, Default: stringdefault.StaticString("terraform")},
			"secret_fingerprint": schema.StringAttribute{Computed: true, PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}},
		},
	}
}

func (m ssoProviderModel) api(ctx context.Context, secret string) (ssoProviderAPI, error) {
	domains, diags := stringsFromList(ctx, m.AllowedDomains)
	if diags.HasError() {
		return ssoProviderAPI{}, errFromDiags(diags)
	}
	return ssoProviderAPI{
		Name: m.Name.ValueString(), Issuer: m.Issuer.ValueString(), ClientID: m.ClientID.ValueString(),
		ClientSecret: secret, AllowedDomains: domains, GroupClaim: m.GroupClaim.ValueString(),
		Enabled: m.Enabled.ValueBool(), ManagedBy: m.ManagedBy.ValueString(),
	}, nil
}

func modelSSO(ctx context.Context, in ssoProviderAPI, fingerprint types.String) (ssoProviderModel, error) {
	domains, diags := listOfStrings(ctx, in.AllowedDomains)
	if diags.HasError() {
		return ssoProviderModel{}, errFromDiags(diags)
	}
	return ssoProviderModel{
		ID: types.StringValue(in.ID), Name: types.StringValue(in.Name), Issuer: types.StringValue(in.Issuer),
		ClientID: types.StringValue(in.ClientID), AllowedDomains: domains, GroupClaim: types.StringValue(in.GroupClaim),
		Enabled: types.BoolValue(in.Enabled), ManagedBy: types.StringValue(in.ManagedBy), SecretFingerprint: fingerprint,
	}, nil
}

func (r *ssoProviderResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan, cfg ssoProviderModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}
	secret := configuredSecret(cfg.ClientSecret)
	body, err := plan.api(ctx, secret)
	if err != nil {
		resp.Diagnostics.AddError("create sso provider", err.Error())
		return
	}
	out, err := r.client.CreateSSOProvider(ctx, body)
	if err != nil {
		resp.Diagnostics.AddError("create sso provider", err.Error())
		return
	}
	model, err := modelSSO(ctx, out, types.StringValue(credentialFingerprint(secret)))
	if err != nil {
		resp.Diagnostics.AddError("create sso provider", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, model)...)
}

func (r *ssoProviderResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state ssoProviderModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	out, err := r.client.GetSSOProvider(ctx, state.ID.ValueString())
	if notFound(err) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("read sso provider", err.Error())
		return
	}
	model, err := modelSSO(ctx, out, state.SecretFingerprint)
	if err != nil {
		resp.Diagnostics.AddError("read sso provider", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, model)...)
}

func (r *ssoProviderResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, cfg ssoProviderModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}
	secret := configuredSecret(cfg.ClientSecret)
	body, err := plan.api(ctx, secret)
	if err != nil {
		resp.Diagnostics.AddError("update sso provider", err.Error())
		return
	}
	out, err := r.client.UpdateSSOProvider(ctx, plan.ID.ValueString(), body)
	if err != nil {
		resp.Diagnostics.AddError("update sso provider", err.Error())
		return
	}
	fingerprint := plan.SecretFingerprint
	if fingerprint.IsNull() || fingerprint.IsUnknown() {
		fingerprint = types.StringValue(credentialFingerprint(secret))
	}
	model, err := modelSSO(ctx, out, fingerprint)
	if err != nil {
		resp.Diagnostics.AddError("update sso provider", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, model)...)
}

func (r *ssoProviderResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state ssoProviderModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.DeleteSSOProvider(ctx, state.ID.ValueString()); err != nil && !notFound(err) {
		resp.Diagnostics.AddError("delete sso provider", err.Error())
	}
}
func (r *ssoProviderResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
func (r *ssoProviderResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	if req.Plan.Raw.IsNull() {
		return
	}
	var cfg, plan ssoProviderModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	plan.ClientSecret = types.StringNull()
	prior := types.StringNull()
	if !req.State.Raw.IsNull() {
		var state ssoProviderModel
		resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
		if resp.Diagnostics.HasError() {
			return
		}
		prior = state.SecretFingerprint
	}
	plan.SecretFingerprint = nextFingerprint(req.State.Raw.IsNull(), prior, []types.String{cfg.ClientSecret})
	resp.Diagnostics.Append(resp.Plan.Set(ctx, plan)...)
}

type roleBindingAPI struct {
	ID         string `json:"id,omitempty"`
	ProviderID string `json:"provider_id"`
	Group      string `json:"group"`
	Role       string `json:"role"`
	ManagedBy  string `json:"managed_by,omitempty"`
}

func (c *Client) CreateRoleBinding(ctx context.Context, in roleBindingAPI) (roleBindingAPI, error) {
	var out roleBindingAPI
	err := c.do(ctx, http.MethodPost, "/api/v1/sso/role-bindings", in, &out)
	return out, err
}
func (c *Client) GetRoleBinding(ctx context.Context, id string) (roleBindingAPI, error) {
	var out roleBindingAPI
	err := c.do(ctx, http.MethodGet, "/api/v1/sso/role-bindings/"+id, nil, &out)
	return out, err
}
func (c *Client) UpdateRoleBinding(ctx context.Context, id string, in roleBindingAPI) (roleBindingAPI, error) {
	var out roleBindingAPI
	err := c.do(ctx, http.MethodPut, "/api/v1/sso/role-bindings/"+id, in, &out)
	return out, err
}
func (c *Client) DeleteRoleBinding(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodDelete, "/api/v1/sso/role-bindings/"+id, nil, nil)
}

type roleBindingResource struct{ client *Client }

func newRoleBindingResource() resource.Resource { return &roleBindingResource{} }

func (r *roleBindingResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_role_binding"
}
func (r *roleBindingResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.client = configureClient(req, resp)
}

type roleBindingModel struct {
	ID         types.String `tfsdk:"id"`
	ProviderID types.String `tfsdk:"provider_id"`
	Group      types.String `tfsdk:"group"`
	Role       types.String `tfsdk:"role"`
	ManagedBy  types.String `tfsdk:"managed_by"`
}

func (r *roleBindingResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Maps an IdP group to viewer, operator, or admin. Those roles use the existing token scopes. A group of * matches every user of the provider. The highest matching role wins. Binding changes apply on the next request; group membership changes apply on the next login.",
		Attributes: map[string]schema.Attribute{
			"id":          schema.StringAttribute{Computed: true, PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}},
			"provider_id": schema.StringAttribute{Required: true},
			"group":       schema.StringAttribute{Required: true, Description: "IdP group, or * for every authenticated user of this provider."},
			"role":        schema.StringAttribute{Required: true, Description: "viewer, operator, or admin."},
			"managed_by":  schema.StringAttribute{Optional: true, Computed: true, Default: stringdefault.StaticString("terraform")},
		},
	}
}

func modelRoleBinding(in roleBindingAPI) roleBindingModel {
	return roleBindingModel{
		ID: types.StringValue(in.ID), ProviderID: types.StringValue(in.ProviderID),
		Group: types.StringValue(in.Group), Role: types.StringValue(in.Role), ManagedBy: types.StringValue(in.ManagedBy),
	}
}

func (r *roleBindingResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan roleBindingModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	out, err := r.client.CreateRoleBinding(ctx, roleBindingAPI{
		ProviderID: plan.ProviderID.ValueString(), Group: plan.Group.ValueString(),
		Role: plan.Role.ValueString(), ManagedBy: plan.ManagedBy.ValueString(),
	})
	if err != nil {
		resp.Diagnostics.AddError("create role binding", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, modelRoleBinding(out))...)
}
func (r *roleBindingResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state roleBindingModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	out, err := r.client.GetRoleBinding(ctx, state.ID.ValueString())
	if notFound(err) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("read role binding", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, modelRoleBinding(out))...)
}
func (r *roleBindingResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan roleBindingModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	out, err := r.client.UpdateRoleBinding(ctx, plan.ID.ValueString(), roleBindingAPI{
		ProviderID: plan.ProviderID.ValueString(), Group: plan.Group.ValueString(),
		Role: plan.Role.ValueString(), ManagedBy: plan.ManagedBy.ValueString(),
	})
	if err != nil {
		resp.Diagnostics.AddError("update role binding", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, modelRoleBinding(out))...)
}
func (r *roleBindingResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state roleBindingModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.DeleteRoleBinding(ctx, state.ID.ValueString()); err != nil && !notFound(err) {
		resp.Diagnostics.AddError("delete role binding", err.Error())
	}
}
func (r *roleBindingResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
