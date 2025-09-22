# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833092");
  script_version("2025-04-25T15:41:53+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-04-25 15:41:53 +0000 (Fri, 25 Apr 2025)");
  script_tag(name:"creation_date", value:"2024-03-04 07:16:23 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for seamonkey (openSUSE-SU-2022:10089-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSEBackportsSLE-15-SP4");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2022:10089-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/SPQVTYMT2NQZUAJYM6IUEEVD4CRRPTNG");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'seamonkey'
  package(s) announced via the openSUSE-SU-2022:10089-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for seamonkey fixes the following issues:
  update to SeaMonkey 2.53.13

  * Updates to devtools.

  * Updates to build configuration.

  * Starting the switch from Python 2 to Python 3 in the build system.

  * Removal of array comprehensions, legacy iterators and generators bug
         1414340 and bug 1098412.

  * Adding initial optional chaining and Promise.allSettled() support.

  * SeaMonkey 2.53.13 uses the same backend as Firefox and contains the
         relevant Firefox 60.8 security fixes.

  * SeaMonkey 2.53.13 shares most parts of the mail and news code with
         Thunderbird. Please read the Thunderbird 60.8.0 release notes for
         specific security fixes in this release.

  * Additional important security fixes up to Current Firefox 91.11 and
         Thunderbird 91.11 ESR plus many enhancements have been backported. We
         will continue to enhance SeaMonkey security in subsequent 2.53.x beta
         and release versions as fast as we are able to.
  update to SeaMonkey 2.53.12

  * Format Toolbar forgets its hidden status when switching to other view
         modes bug 1719020.

  * Remove obsolete plugin code from SeaMonkey bug 1762733.

  * Fix a few strict warnings in SeaMonkey bug 1755553.

  * Remove Run Flash from Site permissions and page info bug 1758289.

  * Use fixIterator and replace use of removeItemAt in FilterListDialog
         bug 1756359.

  * Remove RDF usage in tabmail.js bug 1758282.

  * Implement 'Edit Template' and 'New Message From Template' commands and
         UI bug 1759376.

  * [SM] Implement 'Edit Draft' command and hide it when not in a draft
         folder (port Thunderbird bug 1106412) bug 1256716.

  * Messages in Template folder need 'Edit Template' button in header
         (like for Drafts) bug 80280.

  * Refactor and simplify the feed Subscribe dialog options updates bug
         1420473.

  * Add system memory and disk size and placeDB page limit to
         about:support bug 1753729.

  * Remove warning about missing plugins in SeaMonkey 2.53 and 2.57 bug
         1755558.

  * SeaMonkey 2.53.12 uses the same backend as Firefox and contains the
         relevant Firefox 60.8 security fixes.

  * SeaMonkey 2.53.12 shares most parts of the mail and news code with
         Thunderbird. Please read the Thunderbird 60.8.0 release notes for
         specific security fixes in this release.

  * Additional important security fixes up to Current Firefox 91.9 and
         Thunderbird 91.9 ESR plus many enhancem ...

  Description truncated. Please see the references for more information.");

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

  if(!isnull(res = isrpmvuln(pkg:"seamonkey", rpm:"seamonkey~2.53.13~bp154.2.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"seamonkey-debuginfo", rpm:"seamonkey-debuginfo~2.53.13~bp154.2.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"seamonkey-debugsource", rpm:"seamonkey-debugsource~2.53.13~bp154.2.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"seamonkey-dom-inspector", rpm:"seamonkey-dom-inspector~2.53.13~bp154.2.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"seamonkey-irc", rpm:"seamonkey-irc~2.53.13~bp154.2.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"seamonkey", rpm:"seamonkey~2.53.13~bp154.2.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"seamonkey-debuginfo", rpm:"seamonkey-debuginfo~2.53.13~bp154.2.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"seamonkey-debugsource", rpm:"seamonkey-debugsource~2.53.13~bp154.2.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"seamonkey-dom-inspector", rpm:"seamonkey-dom-inspector~2.53.13~bp154.2.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"seamonkey-irc", rpm:"seamonkey-irc~2.53.13~bp154.2.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
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
