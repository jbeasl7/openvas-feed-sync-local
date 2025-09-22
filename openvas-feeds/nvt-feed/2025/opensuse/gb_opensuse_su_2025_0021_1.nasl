# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.1.2025.0021.1");
  script_cve_id("CVE-2024-52308");
  script_tag(name:"creation_date", value:"2025-02-18 11:01:57 +0000 (Tue, 18 Feb 2025)");
  script_version("2025-02-26T05:38:41+0000");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-11-20 15:07:43 +0000 (Wed, 20 Nov 2024)");

  script_name("openSUSE Security Advisory (openSUSE-SU-2025:0021-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2025:0021-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/HUMKXZZVR2XTEF5OINR7OTNWNR5IVCYQ/");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233387");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gh' package(s) announced via the openSUSE-SU-2025:0021-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for gh fixes the following issues:

- Update to version 2.65.0:
 * Bump cli/go-gh for indirect security vulnerability
 * Panic mustParseTrackingRef if format is incorrect
 * Move trackingRef into pr create package
 * Make tryDetermineTrackingRef tests more respective of reality
 * Rework tryDetermineTrackingRef tests
 * Avoid pointer return from determineTrackingBranch
 * Doc determineTrackingBranch
 * Don't use pointer for determineTrackingBranch branchConfig
 * Panic if tracking ref can't be reconstructed
 * Document and rework pr create tracking branch lookup
 * Upgrade generated workflows
 * Fixed test for stdout in non-tty use case of repo fork
 * Fix test
 * Alternative: remove LocalBranch from BranchConfig
 * Set LocalBranch even if the git config fails
 * Add test for permissions check for security and analysis edits (#1)
 * print repo url to stdout
 * Update pkg/cmd/auth/login/login.go
 * Move mention of classic token to correct line
 * Separate type decrarations
 * Add mention of classic token in gh auth login docs
 * Update pkg/cmd/repo/create/create.go
 * docs(repo): make explicit which branch is used when creating a repo
 * fix(repo fork): add non-TTY output when fork is newly created
 * Move api call to editRun
 * Complete get -> list renaming
 * Better error testing for autolink TestListRun
 * Decode instead of unmarshal
 * Use 'list' instead of 'get' for autolink list type and method
 * Remove NewAutolinkClient
 * Break out autolink list json fields test
 * PR nits
 * Refactor autolink subcommands into their own packages
 * Whitespace
 * Refactor out early return in test code
 * Add testing for AutoLinkGetter
 * Refactor autolink list and test to use http interface for simpler testing
 * Apply PR comment changes
 * Introduce repo autolinks list commands
 * Remove release discussion posts and clean up related block in deployment yml
 * Extract logic into helper function
 * add pending status for workflow runs
 * Feat: Allow setting security_and_analysis settings in gh repo edit
 * Upgrade golang.org/x/net to v0.33.0
 * Document SmartBaseRepoFunc
 * Document BaseRepoFunc
 * Update releasing.md
 * Document how to set gh-merge-base

- Update to version 2.64.0:
 * add test for different SAN and SourceRepositoryURI values
 * add test for signerRepo and tenant
 * add some more fields to test that san, sanregex are set properly
 * Bump github.com/cpuguy83/go-md2man/v2 from 2.0.5 to 2.0.6
 * update san and sanregex configuration for readability
 * reduce duplication when creating policy content
 * tweak output of build policy info
 * Name conditionals in PR finder
 * Support pr view for intra-org forks
 * Return err instead of silentError in merge queue check
 * linting pointed out this var is no longer used
 * Removed fun, but inaccessible ASCII header
 * further tweaks to the long description
 * Exit on pr merge with `-d` and merge queue
 * Addressed ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'gh' package(s) on openSUSE Leap 15.6.");

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

if(release == "openSUSELeap15.6") {

  if(!isnull(res = isrpmvuln(pkg:"gh", rpm:"gh~2.65.0~bp156.2.17.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gh-bash-completion", rpm:"gh-bash-completion~2.65.0~bp156.2.17.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gh-fish-completion", rpm:"gh-fish-completion~2.65.0~bp156.2.17.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gh-zsh-completion", rpm:"gh-zsh-completion~2.65.0~bp156.2.17.1", rls:"openSUSELeap15.6"))) {
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
