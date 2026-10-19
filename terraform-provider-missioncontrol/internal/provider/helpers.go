package provider

import (
	"bytes"
	"context"
	"encoding/json"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
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

func compactJSON(s string) (string, error) {
	if s == "" {
		return "{}", nil
	}
	var buf bytes.Buffer
	if err := json.Compact(&buf, []byte(s)); err != nil {
		return "", err
	}
	return buf.String(), nil
}

func rawJSON(s string) (json.RawMessage, error) {
	c, err := compactJSON(s)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(c), nil
}

func emptyList() types.List {
	return types.ListValueMust(types.StringType, []attr.Value{})
}
