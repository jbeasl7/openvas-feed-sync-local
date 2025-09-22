# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833700");
  script_version("2025-04-25T15:41:53+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-04-25 15:41:53 +0000 (Fri, 25 Apr 2025)");
  script_tag(name:"creation_date", value:"2024-03-04 07:16:17 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for seamonkey (openSUSE-SU-2023:0087-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSEBackportsSLE-15-SP4");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2023:0087-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/3UMIV6D54D4VEGRKGLLU7HOOQEY4RXR6");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'seamonkey'
  package(s) announced via the openSUSE-SU-2023:0087-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"SeaMonkey was updated to 2.53.16:

  * No throbber in plaintext editor bug 85498.

  * Remove unused gridlines class from EdAdvancedEdit bug 1806632.

  * Remove ESR 91 links from debugQA bug 1804534.

  * Rename devtools/shim to devtools/startup bug 1812367.

  * Remove unused seltype=textcell css bug 1806653.

  * Implement new shared tree styling bug 1807802.

  * Use `win.focus()` in macWindowMenu.js bug 1807817.

  * Remove WCAP provider bug 1579020.

  * Remove ftp/file tree view support bug 1239239.

  * Change calendar list tree to a list bug 1561530.

  * Various other updates to the calendar code.

  * Continue the switch from Python 2 to Python 3 in the build system.

  * Verified compatibility with Rust 1.66.1.

  * SeaMonkey 2.53.16 uses the same backend as Firefox and contains the
       relevant Firefox 60.8 security fixes.

  * SeaMonkey 2.53.16 shares most parts of the mail and news code with
       Thunderbird. Please read the Thunderbird 60.8.0 release notes for
       specific security fixes in this release.

  * Additional important security fixes up to Current Firefox 102.9 and
       Thunderbird 102.9 ESR plus many enhancements have been backported. We
       will continue to enhance SeaMonkey security in subsequent 2.53.x beta
       and release versions as fast as we are able to.");

  script_tag(name:"affected", value:"'seamonkey' package(s) on openSUSE Backports SLE-15-SP4.");

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

if(release == "openSUSEBackportsSLE-15-SP4") {

  if(!isnull(res = isrpmvuln(pkg:"seamonkey", rpm:"seamonkey~2.53.16~bp154.2.6.2", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"seamonkey-debuginfo", rpm:"seamonkey-debuginfo~2.53.16~bp154.2.6.2", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"seamonkey-debugsource", rpm:"seamonkey-debugsource~2.53.16~bp154.2.6.2", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"seamonkey-dom-inspector", rpm:"seamonkey-dom-inspector~2.53.16~bp154.2.6.2", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"seamonkey-irc", rpm:"seamonkey-irc~2.53.16~bp154.2.6.2", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"seamonkey", rpm:"seamonkey~2.53.16~bp154.2.6.2", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"seamonkey-debuginfo", rpm:"seamonkey-debuginfo~2.53.16~bp154.2.6.2", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"seamonkey-debugsource", rpm:"seamonkey-debugsource~2.53.16~bp154.2.6.2", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"seamonkey-dom-inspector", rpm:"seamonkey-dom-inspector~2.53.16~bp154.2.6.2", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"seamonkey-irc", rpm:"seamonkey-irc~2.53.16~bp154.2.6.2", rls:"openSUSEBackportsSLE-15-SP4"))) {
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
