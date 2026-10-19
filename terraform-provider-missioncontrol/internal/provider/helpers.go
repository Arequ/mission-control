package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

func stringsFromList(ctx context.Context, list types.List) ([]string, diag.Diagnostics) {
	if list.IsNull() || list.IsUnknown() {
		return []string{}, nil
	}
	var out []string
	diags := list.ElementsAs(ctx, &out, false)
	if out == nil {
		out = []string{}
	}
	return out, diags
}

func listOfStrings(ctx context.Context, in []string) (types.List, diag.Diagnostics) {
	if in == nil {
		in = []string{}
	}
	return types.ListValueFrom(ctx, types.StringType, in)
}

func optString(v types.String) *string {
	if v.IsNull() || v.IsUnknown() || v.ValueString() == "" {
		return nil
	}
	s := v.ValueString()
	return &s
}

func stringValue(p *string) types.String {
	if p == nil || *p == "" {
		return types.StringNull()
	}
	return types.StringValue(*p)
}

// canonicalJSONString sorts object keys so Postgres jsonb and Go's json.Marshal
// compare equal to a config string written in a different order.
func canonicalJSONString(s string) (string, error) {
	if strings.TrimSpace(s) == "" {
		return "{}", nil
	}
	var v any
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		return "", err
	}
	if _, ok := v.(map[string]any); !ok {
		return "", fmt.Errorf("trust_info must be a JSON object")
	}
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func rawJSON(s string) (json.RawMessage, error) {
	c, err := canonicalJSONString(s)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(c), nil
}

// canonicalJSONModifier rewrites planned trust_info into canonical JSON.
type canonicalJSONModifier struct{}

func (canonicalJSONModifier) Description(context.Context) string {
	return "Canonicalize JSON object key order."
}
func (canonicalJSONModifier) MarkdownDescription(ctx context.Context) string {
	return (canonicalJSONModifier{}).Description(ctx)
}
func (canonicalJSONModifier) PlanModifyString(_ context.Context, req planmodifier.StringRequest, resp *planmodifier.StringResponse) {
	if req.PlanValue.IsNull() || req.PlanValue.IsUnknown() {
		return
	}
	c, err := canonicalJSONString(req.PlanValue.ValueString())
	if err != nil {
		resp.Diagnostics.AddAttributeError(req.Path, "invalid JSON", err.Error())
		return
	}
	resp.PlanValue = types.StringValue(c)
}

func emptyList() types.List {
	return types.ListValueMust(types.StringType, []attr.Value{})
}
