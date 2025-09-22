# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856147");
  script_cve_id("CVE-2023-48795");
  script_tag(name:"creation_date", value:"2024-05-23 01:00:32 +0000 (Thu, 23 May 2024)");
  script_version("2025-02-26T05:38:40+0000");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:40 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"cvss_base", value:"5.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-28 18:26:44 +0000 (Thu, 28 Dec 2023)");

  script_name("openSUSE Security Advisory (openSUSE-SU-2024:0135-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2024:0135-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/NJ4UKYMVT5L6QOJVM6JMV6AQINAVT4JW/");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218264");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gitui' package(s) announced via the openSUSE-SU-2024:0135-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for gitui fixes the following issues:

- update to version 0.26.2:
 * respect configuration for remote when fetching (also applies
 to pulling)
 * add : character to sign-off trailer to comply with Conventional
 Commits standard
 * support overriding build_date for reproducible builds
- update vendored dependencies for CVE-2023-48795 (boo#1218264)

- Update to version 0.26.1:
 Added:
 * sign commits using openpgp
 * support ssh commit signing (when user.signingKey and gpg.format
 = ssh of gitconfig are set, ssh-agent isn't yet supported)
 * provide nightly builds (see NIGHTLIES.md)
 * more version info in gitui -V and help popup (including git
 hash)
 * support core.commitChar filtering
 * allow reset in branch popup
 * respect configuration for remote when pushing
 Changed:
 * Make info and error message popups scrollable
 * clarify x86_64 linux binary in artifact names:
 gitui-linux-x86_64.tar.gz (formerly known as musl)
 Fixes:
 * add syntax highlighting support for more file types, e.g.
 Typescript, TOML, etc.

- Update to version 0.25.1:
 Added:
 * support for new-line in text-input (e.g. commit message editor)
 * add syntax highlighting for blame view
 * allow aborting pending commit log search
 * theme.ron now supports customizing line break symbol
 * add confirmation for dialog for undo commit
 * support prepare-commit-msg hook
 * new style block_title_focused to allow customizing title text
 of focused frame/block
 * allow fetch command in both tabs of branchlist popup
 * check branch name validity while typing
 Changed:
 * do not allow tagging when tag.gpgsign enabled until gpg-signing
 is supported
 Fixes:
 * bump yanked dependency bumpalo to fix build from source
 * pin ratatui version to fix building without locked cargo
 install gitui
 * stash window empty after file history popup closes
 * allow push to empty remote
 * better diagnostics for theme file loading
 * fix ordering of commits in diff view

- Update to version 0.24.3:
 * log: fix major lag when going beyond last search hit
 * parallelise log search - performance gain ~100%
 * search message body/summary separately
 * fix commit log not updating after branch switch
 * fix stashlist not updating after pop/drop
 * fix commit log corruption when tabbing in/out while parsing log
 * fix performance problem in big repo with a lot of incoming commits
 * fix error switching to a branch with '/' in the name
 * search commits by message, author or files in diff
 * support 'n'/'p' key to move to the next/prev hunk in diff component
 * simplify theme overrides
 * support for sign-off of commits
 * switched from textwrap to bwrap for text wrapping
 * more logging diagnostics when a repo cannot be
 * added to anaconda
 * visualize empty line substituted with content in diff better
 * checkout branch works with non-empty status report
 * jump to commit by SHA
 * fix commit dialog char count for ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'gitui' package(s) on openSUSE Leap 15.5.");

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

  if(!isnull(res = isrpmvuln(pkg:"gitui", rpm:"gitui~0.26.2~bp155.2.3.1", rls:"openSUSELeap15.5"))) {
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
