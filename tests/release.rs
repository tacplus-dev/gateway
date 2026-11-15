//! The release rules (ci/release-tags.sh, ci/release-notes.sh, ci/release-latest.sh), run against fixture
//! repositories: which image tags a version gets, so a fleet's `MAJOR.MINOR` (tacplus-dev/tacplus#180) only
//! ever moves forward on its own line, which commits its notes list and whether it is Latest; and the build's
//! inputs: the build image a tree pins (ci/build-image.sh) and the launcher release ci/launcher.lock pins
//! (ci/launcher.sh).

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn script(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("ci").join(name)
}

fn run_script(dir: &Path, name: &str, version: &str) -> Output {
    Command::new("bash")
        .arg(script(name))
        .arg(version)
        .current_dir(dir)
        .output()
        .expect("bash")
}

/// What the script prints; the test fails when it fails.
fn run(dir: &Path, name: &str, version: &str) -> String {
    let out = run_script(dir, name, version);
    assert!(
        out.status.success(),
        "{name} {version}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap().trim().to_string()
}

fn git(dir: &Path, args: &[&str]) {
    let out = Command::new("git")
        .args([
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@t",
            "-c",
            "tag.gpgSign=false",
            "-c",
            "commit.gpgSign=false",
        ])
        .args(args)
        .current_dir(dir)
        .output()
        .expect("git");
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// A repository at a fresh path under the target directory, removed first if a previous run left it.
fn repo(name: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join("release")
        .join(name);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    git(&dir, &["init", "-q", "-b", "main"]);
    git(&dir, &["commit", "-q", "--allow-empty", "-m", "first"]);
    dir
}

/// A repository with one commit per tag, tagged in push order; each commit's subject is "change for <tag>".
fn fixture(name: &str, tags: &[&str]) -> PathBuf {
    let dir = repo(name);
    for tag in tags {
        git(
            &dir,
            &[
                "commit",
                "-q",
                "--allow-empty",
                "-m",
                &format!("change for {tag}"),
            ],
        );
        git(&dir, &["tag", tag]);
    }
    dir
}

fn tags(name: &str, tags: &[&str], version: &str) -> String {
    run(&fixture(name, tags), "release-tags.sh", version)
}

#[test]
fn first_release_takes_its_line() {
    assert_eq!(tags("first", &["v0.1.0"], "v0.1.0"), "0.1.0 0.1");
}

#[test]
fn a_patch_moves_its_own_line_and_no_other() {
    // The issue's acceptance: v0.1.1 moves 0.1, and not an older line.
    assert_eq!(
        tags("patch", &["v0.0.3", "v0.1.0", "v0.1.1"], "v0.1.1"),
        "0.1.1 0.1"
    );
}

#[test]
fn a_patch_on_an_older_line_moves_only_that_line() {
    assert_eq!(
        tags("older-line", &["v0.1.0", "v0.2.0", "v0.1.1"], "v0.1.1"),
        "0.1.1 0.1"
    );
}

#[test]
fn an_older_patch_of_the_line_never_moves_it_back() {
    // A re-run of v0.1.1's release after v0.1.2 was pushed.
    assert_eq!(tags("backwards", &["v0.1.1", "v0.1.2"], "v0.1.1"), "0.1.1");
}

#[test]
fn versions_sort_as_numbers_not_text() {
    assert_eq!(
        tags("numeric", &["v0.1.9", "v0.1.10"], "v0.1.10"),
        "0.1.10 0.1"
    );
}

#[test]
fn a_pre_release_gets_only_its_own_tag() {
    assert_eq!(
        tags("pre", &["v0.1.1", "v0.1.2-rc.1"], "v0.1.2-rc.1"),
        "0.1.2-rc.1"
    );
}

#[test]
fn a_pre_release_does_not_hold_back_the_line() {
    assert_eq!(
        tags("pre-behind", &["v0.1.2-rc.1", "v0.1.1"], "v0.1.1"),
        "0.1.1 0.1"
    );
}

#[test]
fn a_version_that_is_not_major_minor_patch_is_refused() {
    let dir = fixture("refused", &["v0.1"]);
    assert!(!run_script(&dir, "release-tags.sh", "v0.1").status.success());
    assert!(!run_script(&dir, "release-notes.sh", "v0.1")
        .status
        .success());
}

/// The change lines of the notes, in order.
fn changes(notes: &str) -> Vec<&str> {
    notes
        .lines()
        .filter_map(|l| l.strip_prefix("- "))
        .map(|l| l.rsplit_once(" (").expect("a commit line ends in (hash)").0)
        .collect()
}

#[test]
fn first_release_notes_list_every_commit() {
    let notes = run(
        &fixture("notes-first", &["v0.1.0"]),
        "release-notes.sh",
        "v0.1.0",
    );
    assert_eq!(changes(&notes), ["change for v0.1.0", "first"]);
}

#[test]
fn notes_list_the_commits_since_the_previous_release() {
    let dir = fixture("notes-since", &["v0.1.0", "v0.1.1"]);
    let notes = run(&dir, "release-notes.sh", "v0.1.1");
    assert!(notes.starts_with("Changes since v0.1.0:"), "{notes}");
    assert_eq!(changes(&notes), ["change for v0.1.1"]);
}

#[test]
fn a_pre_release_is_not_a_previous_release() {
    let dir = fixture("notes-pre", &["v0.1.0", "v0.1.1-rc.1", "v0.1.1"]);
    let notes = run(&dir, "release-notes.sh", "v0.1.1");
    assert_eq!(
        changes(&notes),
        ["change for v0.1.1", "change for v0.1.1-rc.1"]
    );
}

#[test]
fn a_patch_on_an_older_line_is_noted_against_that_line() {
    let dir = repo("notes-older-line");
    git(&dir, &["tag", "v0.1.0"]);
    git(&dir, &["checkout", "-q", "-b", "release/0.1"]);
    git(&dir, &["commit", "-q", "--allow-empty", "-m", "fix on 0.1"]);
    git(&dir, &["checkout", "-q", "main"]);
    git(
        &dir,
        &["commit", "-q", "--allow-empty", "-m", "feature on main"],
    );
    git(&dir, &["tag", "v0.2.0"]);
    git(&dir, &["tag", "v0.1.1", "release/0.1"]);
    let notes = run(&dir, "release-notes.sh", "v0.1.1");
    assert_eq!(changes(&notes), ["fix on 0.1"]);
}

#[test]
fn publishing_v0_1_0_after_v0_1_1_leaves_the_line_on_v0_1_1() {
    // v0.1.0 is published by workflow_dispatch after v0.1.1 was tagged: it gets its own tag only.
    assert_eq!(tags("republish", &["v0.1.0", "v0.1.1"], "v0.1.0"), "0.1.0");
}

fn latest(name: &str, tags: &[&str], version: &str) -> String {
    run(&fixture(name, tags), "release-latest.sh", version)
}

#[test]
fn the_highest_release_is_latest() {
    assert_eq!(
        latest("latest", &["v0.1.0", "v0.1.1"], "v0.1.1"),
        "--latest"
    );
    assert_eq!(
        latest("latest-numeric", &["v0.1.9", "v0.1.10"], "v0.1.10"),
        "--latest"
    );
}

#[test]
fn an_older_release_is_never_latest() {
    // A patch on an older line, and v0.1.0 published after v0.1.1.
    assert_eq!(
        latest(
            "latest-older-line",
            &["v0.1.0", "v0.2.0", "v0.1.1"],
            "v0.1.1"
        ),
        "--latest=false"
    );
    assert_eq!(
        latest("latest-republish", &["v0.1.0", "v0.1.1"], "v0.1.0"),
        "--latest=false"
    );
}

#[test]
fn a_pre_release_is_a_prerelease() {
    assert_eq!(
        latest("latest-pre", &["v0.1.1", "v0.1.2-rc.1"], "v0.1.2-rc.1"),
        "--prerelease"
    );
}

#[test]
fn only_an_existing_tag_is_released() {
    // workflow_dispatch builds a tag that exists; it never makes or moves one.
    let dir = fixture("latest-missing", &["v0.1.0"]);
    assert!(!run_script(&dir, "release-latest.sh", "v0.1.1")
        .status
        .success());
    assert!(!run_script(&dir, "release-latest.sh", "v0.1")
        .status
        .success());
}

/// ci/build-image.sh in `dir` with a `docker` on PATH that prints its arguments: what it would run.
fn in_build_image(dir: &Path, args: &[&str]) -> Output {
    let bin = dir.join(".bin");
    std::fs::create_dir_all(&bin).unwrap();
    let docker = bin.join("docker");
    std::fs::write(&docker, "#!/bin/sh\necho \"docker $*\"\n").unwrap();
    std::fs::set_permissions(&docker, std::fs::Permissions::from_mode(0o755)).unwrap();
    let path = format!("{}:{}", bin.display(), std::env::var("PATH").unwrap());
    Command::new("bash")
        .arg(script("build-image.sh"))
        .arg(dir)
        .args(args)
        .env("PATH", path)
        .output()
        .expect("bash")
}

const LOCK_IMAGE: &str = "ghcr.io/tacplus-dev/tacplus/build:2.6.1@sha256:1111111111111111111111111111111111111111111111111111111111111111";

#[test]
fn the_build_image_is_the_one_the_tree_pins() {
    let dir = repo("image-pinned");
    std::fs::write(
        dir.join("tacplus.lock"),
        format!("tacplus: 2.6.1\nbuild_image: {LOCK_IMAGE}\n"),
    )
    .unwrap();
    let out = in_build_image(&dir, &["just", "gates"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let run = String::from_utf8(out.stdout).unwrap();
    assert!(run.starts_with("docker run "), "{run}");
    assert!(run.contains(LOCK_IMAGE), "{run}");
    assert!(run.contains("just gates"), "{run}");
}

#[test]
fn a_tree_without_a_pin_takes_this_repository_s_and_says_so() {
    // v0.1.0 predates tacplus.lock (#28): it builds with the lock of the workflow's own commit.
    let dir = repo("image-unpinned");
    let out = in_build_image(&dir, &["just", "gates"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let ours = std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("tacplus.lock"))
        .unwrap();
    assert_eq!(
        std::fs::read_to_string(dir.join("tacplus.lock")).unwrap(),
        ours
    );
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("no tacplus.lock"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn a_pin_not_by_digest_is_refused() {
    let dir = repo("image-tagged");
    std::fs::write(
        dir.join("tacplus.lock"),
        "tacplus: 2.6.1\nbuild_image: ghcr.io/tacplus-dev/tacplus/build:2.6.1\n",
    )
    .unwrap();
    assert!(!in_build_image(&dir, &["just", "gates"]).status.success());
}

#[test]
fn every_release_script_is_executable() {
    // The workflow runs them by path: a script committed without its mode fails the release, as kernel's
    // first tag-triggered run did (tacplus-dev/kernel#7).
    let ci = Path::new(env!("CARGO_MANIFEST_DIR")).join("ci");
    let mut scripts = 0;
    for entry in std::fs::read_dir(&ci).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_some_and(|e| e == "sh") {
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert!(
                mode & 0o111 == 0o111,
                "{} is not executable: {mode:o}",
                path.display()
            );
            scripts += 1;
        }
    }
    assert!(scripts >= 6, "{scripts} scripts in ci/");
}

/// The launcher's sha256, as the lock records it.
fn sha256(bytes: &[u8]) -> String {
    use std::io::Write;
    let mut child = Command::new("sha256sum")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("sha256sum");
    child.stdin.take().unwrap().write_all(bytes).unwrap();
    let out = child.wait_with_output().unwrap();
    String::from_utf8(out.stdout).unwrap()[..64].to_string()
}

/// A stand-in for the launcher's releases: `<dir>/<version>/launcher-linux-<arch>` with `bytes`, and a lock
/// naming `version` and `sha` for that binary. Returns (releases dir, lock path).
fn launcher_release(
    name: &str,
    version: &str,
    arch: &str,
    bytes: &[u8],
    sha: &str,
) -> (PathBuf, PathBuf) {
    let dir = repo(name);
    let releases = dir.join("releases");
    std::fs::create_dir_all(releases.join(version)).unwrap();
    std::fs::write(
        releases
            .join(version)
            .join(format!("launcher-linux-{arch}")),
        bytes,
    )
    .unwrap();
    let lock = dir.join("launcher.lock");
    std::fs::write(
        &lock,
        format!("# the pin\nversion: {version}\nlauncher-linux-{arch}: {sha}\n"),
    )
    .unwrap();
    (releases, lock)
}

fn fetch_launcher(releases: &Path, lock: &Path, arch: &str, dest: &Path) -> Output {
    Command::new("bash")
        .arg(script("launcher.sh"))
        .arg(arch)
        .arg(dest)
        .arg(lock)
        .env(
            "LAUNCHER_DOWNLOAD_URL",
            format!("file://{}", releases.display()),
        )
        .output()
        .expect("bash")
}

#[test]
fn the_launcher_is_the_pinned_release_checked_against_its_sha256() {
    let bytes = b"#!/bin/sh\necho launcher\n";
    let (releases, lock) =
        launcher_release("launcher-ok", "v0.1.0", "arm64", bytes, &sha256(bytes));
    let dest = releases.parent().unwrap().join("out");
    let out = fetch_launcher(&releases, &lock, "arm64", &dest);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let binary = dest.join("launcher-linux-arm64");
    assert_eq!(std::fs::read(&binary).unwrap(), bytes);
    assert!(std::fs::metadata(&binary).unwrap().permissions().mode() & 0o111 == 0o111);
    let said = String::from_utf8(out.stdout).unwrap();
    assert!(
        said.contains("v0.1.0") && said.contains(&sha256(bytes)),
        "{said}"
    );
}

#[test]
fn a_launcher_not_matching_the_lock_is_refused_and_nothing_is_left() {
    let bytes = b"not the launcher the lock names\n";
    let (releases, lock) = launcher_release(
        "launcher-bad",
        "v0.1.0",
        "arm64",
        bytes,
        &sha256(b"the launcher the lock names\n"),
    );
    let dest = releases.parent().unwrap().join("out");
    let out = fetch_launcher(&releases, &lock, "arm64", &dest);
    assert!(!out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("sha256"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        std::fs::read_dir(&dest).unwrap().count(),
        0,
        "a refused binary left files in {}",
        dest.display()
    );
}

#[test]
fn an_architecture_the_lock_does_not_name_is_refused() {
    let bytes = b"launcher\n";
    let (releases, lock) =
        launcher_release("launcher-arch", "v0.1.0", "arm64", bytes, &sha256(bytes));
    let dest = releases.parent().unwrap().join("out");
    let out = fetch_launcher(&releases, &lock, "amd64", &dest);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("no sha256 for launcher-linux-amd64"));
}

#[test]
fn the_committed_launcher_lock_names_a_release_and_both_architectures() {
    // What ci/launcher.sh reads in a release: the lock beside it, a vX.Y.Z and a sha256 per architecture the
    // workflow can build (PLATFORMS).
    let lock =
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("ci/launcher.lock"))
            .unwrap();
    let field = |name: &str| {
        lock.lines()
            .find_map(|l| l.strip_prefix(name).and_then(|l| l.strip_prefix(':')))
            .unwrap_or_else(|| panic!("ci/launcher.lock has no {name}"))
            .trim()
            .to_string()
    };
    let version = field("version");
    assert!(
        version.starts_with('v') && version[1..].split('.').count() == 3,
        "{version}"
    );
    for arch in ["amd64", "arm64"] {
        let sha = field(&format!("launcher-linux-{arch}"));
        assert!(
            sha.len() == 64 && sha.chars().all(|c| c.is_ascii_hexdigit()),
            "{arch}: {sha}"
        );
    }
}
