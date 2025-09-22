# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856146");
  script_cve_id("CVE-2024-32650");
  script_tag(name:"creation_date", value:"2024-05-19 01:00:30 +0000 (Sun, 19 May 2024)");
  script_version("2025-02-26T05:38:40+0000");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:40 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("openSUSE Security Advisory (openSUSE-SU-2024:0130-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2024:0130-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/RLZMKRAPDN7C43S56JAGULAWF4RXGB2S/");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223218");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'git-cliff' package(s) announced via the openSUSE-SU-2024:0130-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for git-cliff fixes the following issues:

- update to 2.2.2:
 * (changelog) Allow adding custom context
 * (changelog) Ignore empty lines when using split_commits
 * (parser) Allow matching empty commit body
 * Documentation updates

- update to 2.2.1:
 * Make rendering errors more verbose
 * Support detecting config from project manifest
 * Make the bump version rules configurable
 * bug fixes and documentation updates
- CVE-2024-32650: rust-rustls: Infinite loop with proper client
 input fixes (boo#1223218)

- Update to version 2.1.2:
 * feat(npm): add programmatic API for TypeScript
 * chore(fixtures): enable verbose logging for output
 * refactor(clippy): apply clippy suggestions
 * refactor(changelog): do not output to stdout when prepend is used
 * feat(args): add `--tag-pattern` argument
 * fix(config): fix commit parser regex in the default config
 * fix(github): sanitize the GitHub token in debug logs
 * chore(config): add animation to the header of the changelog
 * refactor(clippy): apply clippy suggestions
 * docs(security): update security policy
 * chore(project): add readme to core package
 * chore(embed): do not allow missing docs
 * chore(config): skip dependabot commits for dev updates
 * docs(readme): mention RustLab 2023 talk
 * chore(config): revamp the configuration files
 * chore(docker): update versions in Dockerfile
 * chore(example): use full links in GitHub templates
 * chore(project): bump MSRV to 1.74.1
 * revert(config): use postprocessors for checking the typos
 * feat(template): support using PR labels in the GitHub template
 * docs(configuration): fix typo
 * feat(args): add `--no-exec` flag for skipping command execution
 * chore(command): explicitly set the directory of command to current dir
 * refactor(ci): use hardcoded workspace members for cargo-msrv command
 * refactor(ci): simplify cargo-msrv installation
 * refactor(clippy): apply clippy suggestions
 * refactor(config): use postprocessors for checking the typos
 * chore(project): update copyright years
 * chore(github): update templates about GitHub integration
 * feat(changelog): set the timestamp of the previous release
 * feat(template): support using PR title in the GitHub template
 * feat(changelog): improve skipping via `.cliffignore` and `--skip-commit`
 * chore(changelog): disable the default behavior of next-version
 * fix(git): sort commits in topological order
 * test(changelog): use the correct version for missing tags
 * chore(changelog): use 0.1.0 as default next release if no tag is found
 * feat(github)!: support integration with GitHub repos
 * refactor(changelog): support `--bump` for processed releases
 * fix(cli): fix broken pipe when stdout is interrupted
 * test(fixtures): update the bumped value output to add prefix
 * feat(changelog): support tag prefixes with `--bump`
 * feat(changelog)!: set tag to `0.0.1` via `--bump` if no tags exist
 * ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'git-cliff' package(s) on openSUSE Leap 15.5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "openSUSELeap15.5") {

  if(!isnull(res = isrpmvuln(pkg:"git-cliff", rpm:"git-cliff~2.2.2~bp155.2.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git-cliff-bash-completion", rpm:"git-cliff-bash-completion~2.2.2~bp155.2.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git-cliff-fish-completion", rpm:"git-cliff-fish-completion~2.2.2~bp155.2.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git-cliff-zsh-completion", rpm:"git-cliff-zsh-completion~2.2.2~bp155.2.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
