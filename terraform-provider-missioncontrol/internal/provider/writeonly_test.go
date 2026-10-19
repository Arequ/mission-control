package provider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/types"
)

func TestImportFingerprintRecordsConfiguredSecret(t *testing.T) {
	secret := types.StringValue("example-crowdstrike-client-secret")
	omitted := []types.String{types.StringNull(), types.StringNull(), types.StringNull()}
	if got := nextFingerprint(false, types.StringNull(), omitted); !got.IsNull() {
		t.Fatalf("import with no configured secret planned %#v", got)
	}
	configured := []types.String{secret, types.StringNull(), types.StringNull()}
	first := nextFingerprint(false, types.StringNull(), configured)
	if first.IsNull() || first.ValueString() == "" {
		t.Fatal("import with a configured secret must plan a fingerprint")
	}
	second := nextFingerprint(false, first, configured)
	if second.ValueString() != first.ValueString() {
		t.Fatalf("second plan changed the fingerprint: %s %s", first.ValueString(), second.ValueString())
	}
	rotated := nextFingerprint(false, first, []types.String{types.StringValue("rotated-secret-value"), types.StringNull(), types.StringNull()})
	if rotated.ValueString() == first.ValueString() {
		t.Fatal("rotation did not change the fingerprint")
	}
	kept := nextFingerprint(false, first, omitted)
	if kept.ValueString() != first.ValueString() {
		t.Fatal("omitted credentials must keep the stored fingerprint")
	}
}
