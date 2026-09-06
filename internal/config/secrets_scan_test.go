package config

// No credential in the repository, and none in its history.
//
// This lives in package config because config is the boundary every credential
// this gateway holds comes in through: DATABASE_URL, REDIS_URL, ADMIN_TOKEN,
// and the provider keys named by a route's upstream_auth_env. The whole design
// is that those values exist only in the process environment, and the way that
// design fails is quietly - someone pastes a working key into a compose file
// or a demo script to get unblocked, and it is in the history forever.
//
// So the check is not "does the current tree look clean", it is both halves:
// every tracked file, and every blob git has ever stored. Anything matching a
// credential shape has to be listed in allowed below, with a reason, and the
// listing is by content hash rather than by filename so that moving a file
// does not silently re-approve it - and so that this file, which forbids
// credential shapes, contains none itself.

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// credentialShapes are the patterns worth failing a build over: the issuing
// formats of the providers this gateway sits in front of, its own key format,
// private key material, and the two generic shapes that catch everything else
// - a secret assigned to a name that says it is one, and a URL carrying a
// password.
var credentialShapes = map[string]*regexp.Regexp{
	"anthropic key":     regexp.MustCompile(`sk-ant-[A-Za-z0-9_-]{20,}`),
	"openai key":        regexp.MustCompile(`sk-(proj-|None-|svcacct-)?[A-Za-z0-9]{32,}`),
	"aws access key id": regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
	"github token":      regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{36,}`),
	"slack token":       regexp.MustCompile(`xox[baprs]-[A-Za-z0-9-]{10,}`),
	"google api key":    regexp.MustCompile(`AIza[0-9A-Za-z_-]{35}`),
	"private key block": regexp.MustCompile(`-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----`),
	// tollgate's own issued key: tg_k<12 hex>_<43 url-safe base64 characters
	// of crypto/rand output. Nothing generates this shape except key issuance,
	// so one in a file is one that was issued and pasted.
	"tollgate api key": regexp.MustCompile(`tg_k[0-9a-f]{12}_[A-Za-z0-9_-]{40,}`),
	"signed jwt":       regexp.MustCompile(`eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{20,}`),
	"url with password": regexp.MustCompile(
		`[a-z][a-z0-9+.-]*://[^\s:/@"']+:[^\s:/@"']+@`),
	"assigned secret": regexp.MustCompile(
		`(?i)(api[_-]?key|secret|passwd|password|token)\s*[:=]\s*["'][^"'\s]{16,}["']`),
}

// allowed maps the SHA-256 of a matched string to why it is in the repository
// on purpose. A hash rather than the text itself, so that this file is not the
// one place in the tree where a credential shape is allowed to sit.
var allowed = map[string]string{
	// docs/demo-setup.sh: the literal string a reader replaces with their own
	// key. It is not a key, it is where one goes.
	"4f901513fc5ae464f5470c68a73e5537cb3ab1a2bcc486579f5a16727571d2b2": "docs/demo-setup.sh, the shell default that names the variable to set",
	"b39cb3919e1527ec5d6a5cd55a9b64d6e5ba6e444e25fec234fa5ba9b3f8aef0": "docs/demo-setup.sh, the same default in its assignment",
	// The local development admin token, in the compose file and the demo
	// script. It guards a stack listening on localhost with a throwaway
	// database behind it, and the compose file says in as many words that it
	// must not be reused anywhere reachable.
	"0473087e46dd3c6a9afe0c353bc48bf8a5478713da5a395937a9c6698b26a2ef": "docs/demo-setup.sh, the local development admin token",
	"ddb31aefdbec46aa461f305507310c29ba359a4ec8fff7eb9c06f8cdd283ae9a": "internal/admin/admin_test.go, the admin token the unit tests construct a server with",
	// README prose showing the shape of a key, with the middle elided.
	"a1a75e974fa516e430093f35402a500fb8fd97262d29dfaa07e7fb75a589bd78": "README.md, an elided key in a usage example",
	// Connection strings for containers that exist only on a developer's
	// machine or inside one CI job, plus two documentation examples of the
	// URL format. None of them names a host that outlives the process.
	"76b63beb5c7bb01b13be51ac8cf292eabce0ae1b91bbb817c6783974cef678f7": "the local and CI Postgres container, whose password is its own name",
	"c3617047f44289e23f23fc3e91013a6f995241b321eb610b998b09eb7c5d6008": "deploy/terraform/postgres.tf, a Terraform interpolation and not a value",
	"1f98909d7fcf83392f21f8c2f993a3ae03af545b6e47f65b2db8d8d5b2c3b051": "internal/config/config.go, the REDIS_URL format in a doc comment",
	"65049d76cd12bbf5731da1cfe52444004d28576d2ff22c2d6354e06cec62dc8d": "internal/config/config_test.go, the same format in a parser test",
	// The one real issued credential in the tree. docs/live.js says why: the
	// landing page drives a deployed gateway, and this key is scoped to a
	// tenant whose only route points at an echo service behind a per-second
	// rate limit. It is published deliberately, and it is the reason this
	// entry exists rather than the pattern being dropped: any OTHER issued key
	// that reaches a file fails this test.
	"ea04f84ad462e0b0545359795a7fa50b45f6459a4a1f9c683c509bf20ea49a33": "docs/live.js, the demo key the public landing page drives the live gateway with",
	// Credential-shaped fixtures the credential tests plant on purpose. Each
	// one exists to be looked for somewhere it must not appear - in a build
	// layer, in an error string, in a span attribute - so the test that proves
	// the gateway does not leak it is the one place its shape has to be
	// written down. None is issued by anything and none opens anything.
	"3021d90eb9437b2d8f30e8363695c4418b5e5f1870801b5c317e9398ee0f572d": "scripts/check-build-context.sh, the PEM header it plants to prove keys stay out of the image",
	"8bcac7908eb950419537b91e19adc83ce2c9cbfdacf4f81157fdadfec11f7017": "scripts/check-build-context.sh, the RSA variant of the same planted header",
	"31427e7897cce4bcfc101fc39935d99c43b09bf8940c5df9c27939682b29949d": "internal/proxy/secret_test.go, the basic-auth userinfo a span attribute must not carry",
	"e287329a5b9aec4187be2de57680cc13a9ac153be611b7540706977dc689dcc0": "internal/proxy/secret_test.go, the query-parameter credential redactedURL must strip",
	"b30f5c57b42d63579f1db23d45f99cdfaedacfb7a21c74c8452e5b8e8d64aaea": "internal/proxy/secret_test.go, the shared provider key the proxy must never echo",
	"06c05df6c4e9c2ed5917e8330e63e0b35583326f823d15cf52b825e5c2899978": "internal/proxy/secret_test.go, the same sentinel unquoted",
	"7c1c2c4baea8218f484705fdeadde41365a29c69e8a9ba505f61a3a9d1fc72d1": "internal/store/dsn_test.go, the DSN password withoutPassword has to redact",
	// deploy/terraform/gcp: three interpolations, not values. Every password in
	// that module is a random_password resource written straight into Secret
	// Manager, so what is in the file is the expression that reads it back.
	"6041d37895fb9242ef70164ce70532cd1d4c0313208c289aab83643c26904b2e": "deploy/terraform/gcp/run.tf, the Secret Manager secret's name and not its value",
	"64b7cd758c91aa9e75fdc95b2dd85c5bcd29efe0eae2e4b4c9db8f827d5649b0": "deploy/terraform/gcp/outputs.tf, a DSN built from a random_password reference",
	"32ce32ebc04a3762f135b61a75b8a470169370185bbc54a8778f60f861c769be": "deploy/terraform/gcp/secrets.tf, the same reference in the per-environment DSN",
	"7c2f78765c03e72d657c3f1d7aeb1abd07ceb4f483cfaffe1ce6bffa05deac8b": "internal/ratelimit/span_test.go, the Redis password a span attribute must not carry",
}

// TestNoCredentialShapeInTheWorkingTree scans every tracked file.
func TestNoCredentialShapeInTheWorkingTree(t *testing.T) {
	root := repoRoot(t)
	out := git(t, root, "ls-files", "-z")
	var findings []finding
	for _, name := range strings.Split(out, "\x00") {
		if name == "" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			continue // a symlink or a file removed since ls-files ran
		}
		findings = append(findings, scanFor(name, string(data))...)
	}
	report(t, findings, "tracked file")
}

// TestNoCredentialShapeAnywhereInTheHistory scans every blob the repository
// has ever stored, including on branches that were deleted and commits that
// were amended away: deleting a leaked credential from the tip does not remove
// it from the object database, and a clone still carries it.
func TestNoCredentialShapeAnywhereInTheHistory(t *testing.T) {
	root := repoRoot(t)
	cmd := exec.Command("git", "cat-file", "--batch-all-objects", "--batch", "--buffer")
	cmd.Dir = root
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("piping git cat-file: %v", err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting git cat-file: %v", err)
	}

	var findings []finding
	var blobs int
	r := bufio.NewReaderSize(stdout, 1<<20)
	for {
		header, err := r.ReadString('\n')
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("reading git cat-file: %v", err)
		}
		fields := strings.Fields(strings.TrimSpace(header))
		if len(fields) < 3 {
			break
		}
		size, err := strconv.Atoi(fields[2])
		if err != nil {
			t.Fatalf("unparseable object size %q", fields[2])
		}
		body := make([]byte, size+1) // git writes a newline after the object
		if _, err := io.ReadFull(r, body); err != nil {
			t.Fatalf("reading object %s: %v", fields[0], err)
		}
		if fields[1] != "blob" {
			continue
		}
		blobs++
		findings = append(findings, scanFor("blob "+fields[0], string(body[:size]))...)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("git cat-file: %v", err)
	}
	if blobs == 0 {
		t.Fatal("scanned no blobs; the history scan proved nothing")
	}
	t.Logf("scanned %d blobs", blobs)
	report(t, findings, "history blob")
}

type finding struct {
	shape string
	where string
	match string
}

func scanFor(where, data string) []finding {
	var out []finding
	for shape, rx := range credentialShapes {
		for _, m := range rx.FindAllString(data, -1) {
			if _, ok := allowed[hashOf(m)]; ok {
				continue
			}
			out = append(out, finding{shape: shape, where: where, match: m})
		}
	}
	return out
}

func hashOf(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// report fails once per distinct matched string, and prints the hash to add to
// allowed alongside a reason if the match is deliberate.
func report(t *testing.T, findings []finding, kind string) {
	t.Helper()
	seen := map[string]finding{}
	for _, f := range findings {
		if _, ok := seen[f.match]; !ok {
			seen[f.match] = f
		}
	}
	keys := make([]string, 0, len(seen))
	for k := range seen {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		f := seen[k]
		t.Errorf("%s shaped like a %s in %s: %q\n"+
			"  if that is deliberate, add %q to allowed with a reason",
			kind, f.shape, f.where, truncate(f.match), hashOf(f.match))
	}
}

func truncate(s string) string {
	if len(s) <= 120 {
		return s
	}
	return s[:120] + "..."
}

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Skip("not inside a git checkout; nothing to scan")
		}
		dir = parent
	}
}

func git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("git %s: %v", strings.Join(args, " "), err)
	}
	return string(out)
}
