package provider

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

func TestCanonicalJSONIgnoresKeyOrder(t *testing.T) {
	got, err := canonicalJSONString(`{"z":1,"a":{"d":1,"b":2}}`)
	if err != nil {
		t.Fatal(err)
	}
	if got != `{"a":{"b":2,"d":1},"z":1}` {
		t.Fatalf("canonical %s", got)
	}
	var resp planmodifier.StringResponse
	(canonicalJSONModifier{}).PlanModifyString(context.Background(), planmodifier.StringRequest{
		PlanValue: types.StringValue(`{"z":1,"a":2}`),
	}, &resp)
	if resp.Diagnostics.HasError() || resp.PlanValue.ValueString() != `{"a":2,"z":1}` {
		t.Fatalf("plan %#v diags=%v", resp.PlanValue, resp.Diagnostics)
	}
}
