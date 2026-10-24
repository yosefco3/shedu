// Package update replaces the shedu binary with a newer signed release: find the latest
// version, download it, verify it (sha256 + minisign), swap it in atomically, restart the
// service, and roll back to the previous binary if the service does not come up.
//
// This is the one documented exception to report-only (see SECURITY.md): the agent writes
// its own binary, and only one that the release key signed.
package update

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"syscall"
	"time"
)

// ReleasePublicKey is the minisign public key that signs shedu releases (the second line
// of minisign.pub, "RW..."), the same key as in packaging/install.sh and README.md.
//
// PLACEHOLDER: until the real key is pasted here, Verify refuses every update, so a build
// made from this source can never replace itself. Edit only this one constant.
const ReleasePublicKey = placeholderKey

const placeholderKey = "REPLACE_WITH_MINISIGN_PUBLIC_KEY"

// ErrNoReleaseKey means this build carries no release key and so cannot update itself.
var ErrNoReleaseKey = errors.New("this build has no release signing key, so it cannot update itself; " +
	"upgrade with install.sh instead: curl -fsSL https://api.getshedu.com/install.sh | sudo bash -s -- --upgrade")

// Defaults for Updater.
const (
	DefaultRepo    = "yosefco3/shedu"
	DefaultDir     = "/var/lib/shedu/update"
	DefaultBinPath = "/usr/local/bin/shedu"
	DefaultService = "shedu"
	maxBinary      = 64 << 20 // a release binary is ~10 MB
	maxSmall       = 64 << 10 // SHA256SUMS, .minisig, API answers
)

var releaseTag = regexp.MustCompile(`^v[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}$`)

// ValidVersion reports whether v is a plain release tag (vX.Y.Z, no pre-release). Only
// those are ever downloaded; the check also keeps the version safe to put in a URL.
func ValidVersion(v string) bool { return releaseTag.MatchString(v) }

// Updater holds everything that touches the outside world, so tests can replace it.
// The zero value works with the defaults above.
type Updater struct {
	PublicKey    string // minisign key ("RW..."); default ReleasePublicKey
	Repo         string // GitHub owner/name; default DefaultRepo
	DownloadBase string // default https://github.com/<Repo>/releases/download
	APIBase      string // default https://api.github.com
	HTTP         *http.Client
	UserAgent    string

	// Cloud returns the latest version the Shedu cloud knows of, or nil when the server is
	// not enrolled. It is only a hint for which version to fetch: nothing is installed
	// without a valid signature.
	Cloud func(ctx context.Context) (string, error)

	Dir     string // download folder; default DefaultDir
	BinPath string // the installed binary; default DefaultBinPath
	Service string // systemd unit; default DefaultService
	Arch    string // default runtime.GOARCH

	// Run executes a command and returns its combined output; default os/exec.
	Run func(ctx context.Context, name string, args ...string) (string, error)
	// Sleep waits between service checks; default time.Sleep.
	Sleep func(time.Duration)
	// UpWithin is how long the restarted service has to come up; default 30s.
	UpWithin time.Duration
}

// Latest returns the newest release: the cloud's answer when enrolled and it gives a
// valid tag, otherwise GitHub's latest (non-draft, non-pre-release) release.
func (u *Updater) Latest(ctx context.Context) (string, error) {
	if u.Cloud != nil {
		if v, err := u.Cloud(ctx); err == nil && ValidVersion(v) {
			return v, nil
		}
	}
	api := u.APIBase
	if api == "" {
		api = "https://api.github.com"
	}
	var rel struct {
		TagName    string `json:"tag_name"`
		Draft      bool   `json:"draft"`
		Prerelease bool   `json:"prerelease"`
	}
	body, err := u.get(ctx, api+"/repos/"+u.repo()+"/releases/latest", maxSmall)
	if err != nil {
		return "", fmt.Errorf("could not ask GitHub for the latest release: %w", err)
	}
	if err := json.Unmarshal(body, &rel); err != nil {
		return "", fmt.Errorf("could not read GitHub's answer: %w", err)
	}
	if rel.Draft || rel.Prerelease || !ValidVersion(rel.TagName) {
		return "", fmt.Errorf("GitHub's latest release %q is not a plain vX.Y.Z release", rel.TagName)
	}
	return rel.TagName, nil
}

// Fetch downloads release v for arch into Dir: the binary, SHA256SUMS and
// SHA256SUMS.minisig. It returns the binary's path. Nothing is trusted yet: call Verify.
func (u *Updater) Fetch(ctx context.Context, v, arch string) (string, error) {
	if !ValidVersion(v) {
		return "", fmt.Errorf("%q is not a release version (vX.Y.Z)", v)
	}
	if arch != "amd64" && arch != "arm64" {
		return "", fmt.Errorf("no shedu release for architecture %q", arch)
	}
	dir := u.dir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	bin := "shedu_linux_" + arch
	for _, name := range []string{bin, "SHA256SUMS", "SHA256SUMS.minisig"} {
		_ = os.Remove(filepath.Join(dir, name)) // never verify a leftover from an older run
	}
	base := u.DownloadBase
	if base == "" {
		base = "https://github.com/" + u.repo() + "/releases/download"
	}
	for _, f := range []struct {
		name string
		max  int64
	}{{"SHA256SUMS", maxSmall}, {"SHA256SUMS.minisig", maxSmall}, {bin, maxBinary}} {
		if err := u.download(ctx, base+"/"+v+"/"+f.name, filepath.Join(dir, f.name), f.max); err != nil {
			if f.name == "SHA256SUMS.minisig" {
				return "", fmt.Errorf("release %s is not signed (no SHA256SUMS.minisig): refusing to update", v)
			}
			return "", fmt.Errorf("download %s: %w", f.name, err)
		}
	}
	return filepath.Join(dir, bin), nil
}

// Verify checks that SHA256SUMS carries a valid release signature naming version v, and
// that the binary's sha256 is the one SHA256SUMS lists for it. A missing signature is an
// error: a self-update never falls back to sha256 alone, since whoever can replace the
// binary on GitHub can replace SHA256SUMS too.
func (u *Updater) Verify(sumsPath, sigPath, binaryPath, v string) error {
	return u.verifyAs(sumsPath, sigPath, binaryPath, filepath.Base(binaryPath), v)
}

// verifyAs is Verify for a file whose SHA256SUMS name differs from its own (the staged copy).
func (u *Updater) verifyAs(sumsPath, sigPath, binaryPath, name, v string) error {
	pk, err := u.releaseKey()
	if err != nil {
		return err
	}
	sums, err := os.ReadFile(sumsPath)
	if err != nil {
		return fmt.Errorf("read SHA256SUMS: %w", err)
	}
	sigFile, err := os.ReadFile(sigPath)
	if err != nil {
		return fmt.Errorf("no signature for SHA256SUMS (%s): refusing to update", filepath.Base(sigPath))
	}
	s, err := VerifyMinisign(pk, sums, sigFile)
	if err != nil {
		return err
	}
	// The trusted comment is signed and names the release ("shedu v0.3.1 SHA256SUMS"), so
	// an older signed SHA256SUMS cannot be passed off as a newer release (a downgrade).
	if !hasField(s.TrustedComment, v) {
		return fmt.Errorf("%w: the signature is for %q, not for %s", ErrSignatureInvalid, s.TrustedComment, v)
	}
	want, ok := lookupSum(sums, name)
	if !ok {
		return fmt.Errorf("SHA256SUMS does not list %s", name)
	}
	got, err := fileSHA256(binaryPath)
	if err != nil {
		return err
	}
	if got != want {
		return fmt.Errorf("checksum mismatch for %s: the download is damaged or was changed", name)
	}
	return nil
}

// CheckKey reports ErrNoReleaseKey when this build carries only the placeholder key, so a
// caller can stop before downloading anything. Verify checks the same again.
func (u *Updater) CheckKey() error {
	_, err := u.releaseKey()
	return err
}

func (u *Updater) releaseKey() (PublicKey, error) {
	key := u.PublicKey
	if key == "" {
		key = ReleasePublicKey
	}
	if key == placeholderKey || strings.TrimSpace(key) == "" {
		return PublicKey{}, ErrNoReleaseKey
	}
	pk, err := ParsePublicKey(key)
	if err != nil {
		return PublicKey{}, fmt.Errorf("the embedded release key is broken: %w", err)
	}
	return pk, nil
}

// Upgrade runs the whole sequence for version v: Fetch, Verify, Apply.
func (u *Updater) Upgrade(ctx context.Context, v string) (Result, error) {
	bin, err := u.Fetch(ctx, v, u.arch())
	if err != nil {
		return Result{}, err
	}
	dir := filepath.Dir(bin)
	if err := u.Verify(filepath.Join(dir, "SHA256SUMS"), filepath.Join(dir, "SHA256SUMS.minisig"), bin, v); err != nil {
		_ = os.Remove(bin)
		return Result{}, err
	}
	return u.Apply(ctx, bin, v)
}

// Result says what Apply did.
type Result struct {
	Restarted  bool // the service was running and came back up on the new binary
	NotRunning bool // the service was not running, so it was not restarted
}

// ErrRolledBack means the new binary was installed but the service did not come up on
// it, so the previous binary was put back.
var ErrRolledBack = errors.New("the service did not come up on the new version; the previous version was restored")

// Apply installs a downloaded binary. It copies it next to BinPath as BinPath.new and
// verifies that copy again against SHA256SUMS and SHA256SUMS.minisig from the binary's
// folder (so the bytes that run as root are the bytes that were signed), checks that it
// reports version v, keeps the current binary as BinPath.prev, swaps the new one in with a
// rename (so there is never a moment without a binary), and restarts the service. If the
// service does not come up within UpWithin, the previous binary is restored.
//
// A cancelled ctx stops nothing after the swap: the restart check and any rollback always
// run to the end.
func (u *Updater) Apply(ctx context.Context, binaryPath, v string) (Result, error) {
	dst := u.binPath()
	if fi, err := os.Lstat(dst); err != nil || !fi.Mode().IsRegular() && fi.Mode()&os.ModeSymlink == 0 {
		return Result{}, fmt.Errorf("%s is not an installed shedu binary; install with install.sh first", dst)
	}
	tmp := dst + ".new"
	if err := copyFile(binaryPath, tmp, 0o755); err != nil {
		return Result{}, fmt.Errorf("could not stage the new binary: %w", err)
	}
	dir := filepath.Dir(binaryPath)
	if err := u.verifyAs(filepath.Join(dir, "SHA256SUMS"), filepath.Join(dir, "SHA256SUMS.minisig"),
		tmp, filepath.Base(binaryPath), v); err != nil {
		_ = os.Remove(tmp)
		return Result{}, err
	}
	out, err := u.run(ctx, tmp, "version")
	if got := strings.TrimSpace(out); err != nil || got != v {
		_ = os.Remove(tmp)
		return Result{}, fmt.Errorf("the new binary did not report %s (got %q): not installed", v, got)
	}
	// Keep the current binary as .prev: link (or copy) it to .prev.tmp first, so an older
	// .prev is replaced only once the new one exists.
	prev := dst + ".prev"
	_ = os.Remove(prev + ".tmp")
	if err := os.Link(dst, prev+".tmp"); err != nil {
		if err := copyFile(dst, prev+".tmp", 0o755); err != nil {
			_ = os.Remove(tmp)
			return Result{}, fmt.Errorf("could not keep the current binary as %s: %w", prev, err)
		}
	}
	if err := os.Rename(prev+".tmp", prev); err != nil {
		_ = os.Remove(tmp)
		_ = os.Remove(prev + ".tmp")
		return Result{}, fmt.Errorf("could not keep the current binary as %s: %w", prev, err)
	}
	if err := os.Rename(tmp, dst); err != nil {
		_ = os.Remove(tmp)
		return Result{}, fmt.Errorf("could not replace %s: %w", dst, err)
	}
	_ = os.Remove(binaryPath)

	ctx = context.WithoutCancel(ctx)
	state, oldPID := u.serviceState(ctx)
	if state != "active" {
		return Result{NotRunning: true}, nil
	}
	// Restart from a transient unit two seconds later, so that a restart asked for from
	// inside the service does not kill the process that asked for it.
	if out, err := u.run(ctx, "systemd-run", "--on-active=2", "--quiet", "systemctl", "restart", u.service()); err != nil {
		return Result{}, u.rollback(ctx, fmt.Errorf("could not schedule the restart: %v %s", err, strings.TrimSpace(out)))
	}
	if u.waitUp(ctx, oldPID) {
		return Result{Restarted: true}, nil
	}
	return Result{}, u.rollback(ctx, ErrRolledBack)
}

// ErrRollbackDown means the previous binary was put back but the service still does not
// run; a person has to look.
var ErrRollbackDown = errors.New("the service did not come up on the new version, the previous version was put back, " +
	"and the service is still not running")

// rollback puts BinPath.prev back, restarts the service on it and checks that it runs.
func (u *Updater) rollback(ctx context.Context, cause error) error {
	dst := u.binPath()
	if err := os.Rename(dst+".prev", dst); err != nil {
		return fmt.Errorf("%v; restoring the previous binary also failed: %v", cause, err)
	}
	_, pid := u.serviceState(ctx)
	if _, err := u.run(ctx, "systemctl", "restart", u.service()); err != nil || !u.waitUp(ctx, pid) {
		return fmt.Errorf("%w (%v)", ErrRollbackDown, cause)
	}
	return cause
}

// waitUp waits until the service runs a new main process and stays active for a few
// seconds (a binary that crashes on start would otherwise look "up" for a moment).
func (u *Updater) waitUp(ctx context.Context, oldPID string) bool {
	within := u.UpWithin
	if within <= 0 {
		within = 30 * time.Second
	}
	const step, settle = time.Second, 10 // longer than the unit's RestartSec=5
	seen, stable := "", 0
	for waited := time.Duration(0); waited < within; waited += step {
		if ctx.Err() != nil {
			return false
		}
		u.sleep(step)
		state, pid := u.serviceState(ctx)
		switch {
		case state == "active" && pid != "0" && pid != "" && pid != oldPID && pid == seen:
			stable++
			if stable >= settle {
				return true
			}
		case state == "active" && pid != "0" && pid != "" && pid != oldPID:
			seen, stable = pid, 1
		default:
			seen, stable = "", 0
		}
	}
	return false
}

// serviceState returns the unit's ActiveState and MainPID ("" when systemd can't say).
func (u *Updater) serviceState(ctx context.Context) (state, pid string) {
	out, err := u.run(ctx, "systemctl", "show", u.service(), "--property=ActiveState", "--property=MainPID")
	if err != nil {
		return "", ""
	}
	for _, line := range strings.Split(out, "\n") {
		k, val, _ := strings.Cut(strings.TrimSpace(line), "=")
		switch k {
		case "ActiveState":
			state = val
		case "MainPID":
			pid = val
		}
	}
	return state, pid
}

// download streams url into path (mode 0600), at most max bytes.
func (u *Updater) download(ctx context.Context, url, path string, max int64) error {
	body, err := u.open(ctx, url)
	if err != nil {
		return err
	}
	defer body.Close()
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	n, err := io.Copy(f, io.LimitReader(body, max+1))
	if err == nil && n > max {
		err = fmt.Errorf("%s is larger than %d bytes", filepath.Base(path), max)
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(path) //nolint:errcheck
	}
	return err
}

func (u *Updater) get(ctx context.Context, url string, max int64) ([]byte, error) {
	body, err := u.open(ctx, url)
	if err != nil {
		return nil, err
	}
	defer body.Close()
	b, err := io.ReadAll(io.LimitReader(body, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("answer from %s is larger than %d bytes", url, max)
	}
	return b, nil
}

// open GETs url and returns the body of a 200 answer. Redirects from https to plain http
// are refused (GitHub sends release downloads to its object store over https).
func (u *Updater) open(ctx context.Context, url string) (io.ReadCloser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	ua := u.UserAgent
	if ua == "" {
		ua = "shedu-agent"
	}
	req.Header.Set("User-Agent", ua)
	hc := u.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 5 * time.Minute, CheckRedirect: httpsOnlyRedirects}
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("HTTP %d from %s", resp.StatusCode, req.URL.Host)
	}
	return resp.Body, nil
}

func httpsOnlyRedirects(req *http.Request, via []*http.Request) error {
	if len(via) >= 10 {
		return errors.New("too many redirects")
	}
	if via[0].URL.Scheme == "https" && req.URL.Scheme != "https" {
		return errors.New("refusing a redirect from https to " + req.URL.Scheme)
	}
	return nil
}

// Lock takes an exclusive lock on Dir/lock so that two upgrades never run at once. Call
// the returned function to release it.
func (u *Updater) Lock() (func(), error) {
	if err := os.MkdirAll(u.dir(), 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(u.dir(), "lock"), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, errors.New("another shedu upgrade is running")
	}
	return func() { syscall.Flock(int(f.Fd()), syscall.LOCK_UN); f.Close() }, nil //nolint:errcheck
}

func (u *Updater) run(ctx context.Context, name string, args ...string) (string, error) {
	if u.Run != nil {
		return u.Run(ctx, name, args...)
	}
	cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	out, err := exec.CommandContext(cctx, name, args...).CombinedOutput()
	return string(out), err
}

func (u *Updater) sleep(d time.Duration) {
	if u.Sleep != nil {
		u.Sleep(d)
		return
	}
	time.Sleep(d)
}

func (u *Updater) repo() string    { return or(u.Repo, DefaultRepo) }
func (u *Updater) dir() string     { return or(u.Dir, DefaultDir) }
func (u *Updater) binPath() string { return or(u.BinPath, DefaultBinPath) }
func (u *Updater) service() string { return or(u.Service, DefaultService) }
func (u *Updater) arch() string    { return or(u.Arch, runtime.GOARCH) }

func or(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

func hasField(s, want string) bool {
	for _, f := range strings.Fields(s) {
		if f == want {
			return true
		}
	}
	return false
}

// lookupSum finds name's hash in sha256sum output ("<hex>  <name>" or "<hex> *<name>").
func lookupSum(sums []byte, name string) (string, bool) {
	sc := bufio.NewScanner(bytes.NewReader(sums))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 2 && strings.TrimPrefix(f[1], "*") == name && len(f[0]) == 64 {
			return strings.ToLower(f[0]), true
		}
	}
	return "", false
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// copyFile writes src to dst with mode and fsyncs it, replacing dst.
func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	_ = os.Remove(dst)
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		os.Remove(dst)
		return err
	}
	if err := out.Sync(); err != nil {
		out.Close()
		os.Remove(dst)
		return err
	}
	if err := out.Close(); err != nil {
		os.Remove(dst)
		return err
	}
	return os.Chmod(dst, mode) // OpenFile's mode is masked by the umask
}
