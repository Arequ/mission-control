package auth

import "testing"

func TestSecretEqual(t *testing.T) {
	if !SecretEqual("mc_dev_repo_token", "mc_dev_repo_token") {
		t.Fatal("equal secrets differed")
	}
	if SecretEqual("mc_dev_repo_token", "mc_dev_repo_token ") {
		t.Fatal("unequal secrets matched")
	}
	if SecretEqual("", "x") || SecretEqual("short", "much-longer-secret") {
		t.Fatal("length mismatch matched")
	}
}
