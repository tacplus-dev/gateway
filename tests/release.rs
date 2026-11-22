//! The release rules (ci/release-notes.sh, ci/release-latest.sh), run against fixture repositories: which
//! commits a release's notes list, and whether its GitHub release is Latest, so an older line's patch (or an
//! older release published late) never takes Latest from the highest release.

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

#[test]
fn a_version_that_is_not_major_minor_patch_is_refused() {
    let dir = fixture("refused", &["v0.1"]);
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
    assert!(scripts >= 2, "{scripts} scripts in ci/");
}

