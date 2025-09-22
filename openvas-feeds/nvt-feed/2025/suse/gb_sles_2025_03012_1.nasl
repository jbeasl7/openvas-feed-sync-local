# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.03012.1");
  script_cve_id("CVE-2025-27613", "CVE-2025-27614", "CVE-2025-46835", "CVE-2025-48384", "CVE-2025-48385");
  script_tag(name:"creation_date", value:"2025-09-01 04:17:40 +0000 (Mon, 01 Sep 2025)");
  script_version("2025-09-01T05:39:44+0000");
  script_tag(name:"last_modification", value:"2025-09-01 05:39:44 +0000 (Mon, 01 Sep 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:03012-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP6)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:03012-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-202503012-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1212476");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1216545");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218588");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218664");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1243197");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245938");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245939");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245942");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245943");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245946");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-August/041415.html");
  script_xref(name:"URL", value:"https://raw.githubusercontent.com/git/git/master/Documentation/RelNotes/2.43.1.adoc");
  script_xref(name:"URL", value:"https://raw.githubusercontent.com/git/git/master/Documentation/RelNotes/2.43.2.adoc");
  script_xref(name:"URL", value:"https://raw.githubusercontent.com/git/git/master/Documentation/RelNotes/2.43.3.adoc");
  script_xref(name:"URL", value:"https://raw.githubusercontent.com/git/git/master/Documentation/RelNotes/2.44.0.adoc");
  script_xref(name:"URL", value:"https://raw.githubusercontent.com/git/git/master/Documentation/RelNotes/2.45.0.adoc");
  script_xref(name:"URL", value:"https://raw.githubusercontent.com/git/git/master/Documentation/RelNotes/2.45.1.adoc");
  script_xref(name:"URL", value:"https://raw.githubusercontent.com/git/git/master/Documentation/RelNotes/2.45.2.adoc");
  script_xref(name:"URL", value:"https://raw.githubusercontent.com/git/git/master/Documentation/RelNotes/2.45.3.adoc");
  script_xref(name:"URL", value:"https://raw.githubusercontent.com/git/git/master/Documentation/RelNotes/2.46.0.adoc");
  script_xref(name:"URL", value:"https://raw.githubusercontent.com/git/git/master/Documentation/RelNotes/2.46.1.adoc");
  script_xref(name:"URL", value:"https://raw.githubusercontent.com/git/git/master/Documentation/RelNotes/2.46.2.adoc");
  script_xref(name:"URL", value:"https://raw.githubusercontent.com/git/git/master/Documentation/RelNotes/2.47.0.adoc");
  script_xref(name:"URL", value:"https://raw.githubusercontent.com/git/git/master/Documentation/RelNotes/2.47.1.adoc");
  script_xref(name:"URL", value:"https://raw.githubusercontent.com/git/git/master/Documentation/RelNotes/2.48.0.adoc");
  script_xref(name:"URL", value:"https://raw.githubusercontent.com/git/git/master/Documentation/RelNotes/2.48.1.adoc");
  script_xref(name:"URL", value:"https://raw.githubusercontent.com/git/git/master/Documentation/RelNotes/2.49.0.adoc");
  script_xref(name:"URL", value:"https://raw.githubusercontent.com/git/git/master/Documentation/RelNotes/2.50.0.adoc");
  script_xref(name:"URL", value:"https://raw.githubusercontent.com/git/git/master/Documentation/RelNotes/2.50.1.adoc");
  script_xref(name:"URL", value:"https://raw.githubusercontent.com/git/git/master/Documentation/RelNotes/2.51.0.adoc");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'git-lfs, obs-scm-bridge, python-PyYAML, security update for git' package(s) announced via the SUSE-SU-2025:03012-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for git, git-lfs, obs-scm-bridge, python-PyYAML fixes the following issues:

git was updated from version 2.43.0 to 2.51.0 (bsc#1243197):

- Security issues fixed:

 * CVE-2025-27613 Fixed arbitrary writable file creation and truncation in Gitk(bsc#1245938)
 * CVE-2025-27614 Fixed arbitrary script execution via repository clonation in gitk(bsc#1245939)
 * CVE-2025-46835 Fixed arbitrary writable file creation in Git GUI when untrusted repository is cloned (bsc#1245942)
 * CVE-2025-48384 Fixed the unintentional execution of a script after checkout due to CRLF transforming (bsc#1245943)
 * CVE-2025-48385 Fixed arbitrary code execution due to protocol injection via fetching advertised bundle(bsc#1245946)

- Other changes and bugs fixed:

- Other changes and bugs fixed:

 * Added SHA256 support (bsc#1243197)
 * Git moved to /usr/libexec/git/git and updated AppArmor profile
 accordingly (bsc#1218588)
 * gitweb AppArmor profile: allow reading etc/gitweb-common.conf (bsc#1218664)
 * Do not replace apparmor configuration (bsc#1216545)
 * Fixed the Python version required (bsc#1212476)

- Version Updates Release Notes:

 * [links moved to references]

git-lfs is included in version 3.7.0.

python-PyYAML was updated from version 6.0.1 to 6.0.2:

- Added support for Cython 3.x and Python 3.13

obs-scm-bridge was updated from version 0.5.4 to 0.7.4:

- New Features and Improvements:

 * Manifest File Support: Support has been added for a `_manifest file`, which serves as a successor to the `_subdirs`
 file.
 * Control Over Git Information: A new noobsinfo query parameter was added to hide git information in source and binary
 files.
 * Enhanced Submodule Handling: The system now records the configured branch of submodules and stays on that branch
 during checkout.
 * Git SHA Tracking: In project mode, the tool now uses git SHA sums instead of md5sum to track package sources.
 * SSH URL Support: ssh:// SCM URLs can now be used.
 * Improved Error Messages: Error reporting for invalid files within package subdirectories has been improved.
 * Standardized Config Location: In project mode, the _config file is now always located in the top-level directory,
 even when using subdirs.
 * Reduced Unnecessary Changes: In project mode, unnecessary modifications to the package meta URL are now avoided.
 * Limit Asset Handling: A new mechanism has been introduced to limit how assets are handled.
 * Branch Information Export: The trackingbranch is now exported to scmsync.obsinfo.

- Bugs fixed:

 * Syntax Fix: A syntax issue was corrected.
 * Git Submodule Parsing: The .gitsubmodule parser was fixed to correctly handle files that contain a mix of spaces and
 tabs.");

  script_tag(name:"affected", value:"'git-lfs, obs-scm-bridge, python-PyYAML, security update for git' package(s) on SUSE Linux Enterprise Server 15-SP6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "SLES15.0SP6") {

  if(!isnull(res = isrpmvuln(pkg:"git-core", rpm:"git-core~2.51.0~150600.3.12.1", rls:"SLES15.0SP6"))) {
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
