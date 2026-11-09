package install

import (
	"os/exec"
	"strings"
	"testing"
)

func TestManifestChecksumSelectsExactArchitecture(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("POSIX shell unavailable")
	}
	source := string(script)
	start := strings.Index(source, "manifest_checksum() {")
	end := start + strings.Index(source[start:], "\n}") + len("\n}")
	function := source[start:end]
	manifest := `{"binaries":[{"name":"noobtunnel_linux_386","sha256":"` + strings.Repeat("a", 64) + `"},{"name":"noobtunnel_linux_amd64.backup","sha256":"` + strings.Repeat("b", 64) + `"},{"name":"noobtunnel_linux_amd64","sha256":"` + strings.Repeat("c", 64) + `"}]}`
	for _, tc := range []struct{ name, want string }{
		{"noobtunnel_linux_386", strings.Repeat("a", 64)},
		{"noobtunnel_linux_amd64", strings.Repeat("c", 64)},
		{"noobtunnel_linux_arm64", ""},
	} {
		cmd := exec.Command(sh, "-c", function+"\nmanifest_checksum \"$1\"", "fixture", tc.name)
		cmd.Stdin = strings.NewReader(manifest)
		out, err := cmd.CombinedOutput()
		if err != nil || strings.TrimSpace(string(out)) != tc.want {
			t.Fatalf("%s: %v %s", tc.name, err, out)
		}
	}
}
