# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.854872");
  script_version("2025-04-25T15:41:53+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-04-25 15:41:53 +0000 (Fri, 25 Apr 2025)");
  script_tag(name:"creation_date", value:"2022-08-04 01:04:48 +0000 (Thu, 04 Aug 2022)");
  script_name("openSUSE: Security Advisory for seamonkey (openSUSE-SU-2022:10077-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.3");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2022:10077-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/W4BTNNYQ76OHG26V7PSUGDZ5A7XAE7HM");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'seamonkey'
  package(s) announced via the openSUSE-SU-2022:10077-1 advisory.");

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
       and release versions as fast as we are able to.");

  script_tag(name:"affected", value:"'seamonkey' package(s) on openSUSE Leap 15.3.");

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

if(release == "openSUSELeap15.3") {

  if(!isnull(res = isrpmvuln(pkg:"seamonkey", rpm:"seamonkey~2.53.13~lp153.17.11.3", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"seamonkey-debuginfo", rpm:"seamonkey-debuginfo~2.53.13~lp153.17.11.3", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"seamonkey-debugsource", rpm:"seamonkey-debugsource~2.53.13~lp153.17.11.3", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"seamonkey-dom-inspector", rpm:"seamonkey-dom-inspector~2.53.13~lp153.17.11.3", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"seamonkey-irc", rpm:"seamonkey-irc~2.53.13~lp153.17.11.3", rls:"openSUSELeap15.3"))) {
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
