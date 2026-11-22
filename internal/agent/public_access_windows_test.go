//go:build windows

package agent

import (
	"os"
	"path/filepath"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestPublicStatusAccessKeepsCredentialsPrivate(t *testing.T) {
	dir := t.TempDir()
	owner, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{{
		AccessPermissions: windows.GENERIC_ALL,
		AccessMode:        windows.GRANT_ACCESS,
		Inheritance:       windows.CONTAINER_INHERIT_ACE | windows.OBJECT_INHERIT_ACE,
		Trustee:           windows.TRUSTEE{TrusteeForm: windows.TRUSTEE_IS_SID, TrusteeValue: windows.TrusteeValueFromSID(owner.User.Sid)},
	}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadIdentity(dir); err != nil {
		t.Fatal(err)
	}
	if err := allowPublicRead(dir, true); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "token"), []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeRuntime(dir, &RuntimeState{}); err != nil {
		t.Fatal(err)
	}
	if err := SaveForwardPolicy(dir, ForwardPolicy{LoopbackOnly: true}); err != nil {
		t.Fatal(err)
	}
	if err := writeRuntime(dir, &RuntimeState{}); err != nil {
		t.Fatal(err)
	}
	for _, entry := range []struct {
		name   string
		public bool
	}{{"", true}, {"runtime.json", true}, {"forward-policy.json", true}, {"identity.json", false}, {"token", false}} {
		path := filepath.Join(dir, entry.name)
		sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
		if err != nil {
			t.Fatal(err)
		}
		dacl, _, err := sd.DACL()
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for i := uint32(0); i < uint32(dacl.AceCount); i++ {
			var ace *windows.ACCESS_ALLOWED_ACE
			if err := windows.GetAce(dacl, i, &ace); err != nil {
				t.Fatal(err)
			}
			sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
			if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || sid.String() != "S-1-5-32-545" {
				continue
			}
			found = true
			if ace.Header.AceFlags != 0 {
				t.Fatal("public read permission must not be inherited")
			}
			if ace.Mask&(windows.FILE_WRITE_DATA|windows.FILE_APPEND_DATA|windows.WRITE_DAC|windows.WRITE_OWNER) != 0 {
				t.Fatal("public metadata must not be writable")
			}
		}
		if found != entry.public {
			t.Fatalf("public access for %s = %v", entry.name, found)
		}
	}
}
