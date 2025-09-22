# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123723");
  script_cve_id("CVE-2013-0775", "CVE-2013-0776", "CVE-2013-0780", "CVE-2013-0782", "CVE-2013-0783");
  script_tag(name:"creation_date", value:"2015-10-06 11:07:41 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Oracle: Security Advisory (ELSA-2013-0271)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=(OracleLinux5|OracleLinux6)");

  script_xref(name:"Advisory-ID", value:"ELSA-2013-0271");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2013-0271.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'devhelp, firefox, libproxy, xulrunner, yelp' package(s) announced via the ELSA-2013-0271 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"firefox
[17.0.3-1.0.1]
- Add firefox-oracle-default-prefs.js and remove the corresponding Red Hat ones

[17.0.3-1]
- Update to 17.0.3 ESR

[17.0.2-4]
- Added NM preferences

[17.0.2-3]
- Update to 17.0.2 ESR

[17.0.1-2]
- Update to 17.0.1 ESR

[17.0-1]
- Update to 17.0 ESR

[17.0-0.2.b4]
- Update to 17 Beta 4

[17.0-0.1.beta1]
- Update to 17 Beta 1


libproxy
[0.3.0-4]
- Rebuild against newer gecko

xulrunner
[17.0.3-1.0.2]
- Increase release number and rebuild.

[17.0.3-1.0.1]
- Replaced xulrunner-redhat-default-prefs.js with xulrunner-oracle-default-prefs.js
- Removed XULRUNNER_VERSION from SOURCE21

[17.0.3-1]
- Update to 17.0.3 ESR

[17.0.2-5]
- Fixed NetworkManager preferences
- Added fix for NM regression (mozbz#791626)

[17.0.2-2]
- Added fix for rhbz#816234 - NFS fix

[17.0.2-1]
- Update to 17.0.2 ESR

[17.0.1-3]
- Update to 17.0.1 ESR

[17.0-1]
- Update to 17.0 ESR

[17.0-0.6.b5]
- Update to 17 Beta 5
- Updated fix for rhbz#872752 - embedded crash

[17.0-0.5.b4]
- Added fix for rhbz#872752 - embedded crash

[17.0-0.4.b4]
- Update to 17 Beta 4

[17.0-0.3.b3]
- Update to 17 Beta 3
- Updated ppc(64) patch (mozbz#746112)

[17.0-0.2.b2]
- Built with system nspr/nss

[17.0-0.1.b2]
- Update to 17 Beta 2

[17.0-0.1.b1]
- Update to 17 Beta 1

yelp
[2.28.1-17]
- Rebuild against gecko 17.0.2

[2.28.1-15]
- Build fixes for gecko 17");

  script_tag(name:"affected", value:"'devhelp, firefox, libproxy, xulrunner, yelp' package(s) on Oracle Linux 5, Oracle Linux 6.");

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

if(release == "OracleLinux5") {

  if(!isnull(res = isrpmvuln(pkg:"devhelp", rpm:"devhelp~0.12~23.el5_9", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"devhelp-devel", rpm:"devhelp-devel~0.12~23.el5_9", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox", rpm:"firefox~17.0.3~1.0.1.el5_9", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xulrunner", rpm:"xulrunner~17.0.3~1.0.1.el5_9", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xulrunner-devel", rpm:"xulrunner-devel~17.0.3~1.0.1.el5_9", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"yelp", rpm:"yelp~2.16.0~30.el5_9", rls:"OracleLinux5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "OracleLinux6") {

  if(!isnull(res = isrpmvuln(pkg:"firefox", rpm:"firefox~17.0.3~1.0.1.el6_3", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libproxy", rpm:"libproxy~0.3.0~4.el6_3", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libproxy-bin", rpm:"libproxy-bin~0.3.0~4.el6_3", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libproxy-devel", rpm:"libproxy-devel~0.3.0~4.el6_3", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libproxy-gnome", rpm:"libproxy-gnome~0.3.0~4.el6_3", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libproxy-kde", rpm:"libproxy-kde~0.3.0~4.el6_3", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libproxy-mozjs", rpm:"libproxy-mozjs~0.3.0~4.el6_3", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libproxy-python", rpm:"libproxy-python~0.3.0~4.el6_3", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libproxy-webkit", rpm:"libproxy-webkit~0.3.0~4.el6_3", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xulrunner", rpm:"xulrunner~17.0.3~1.0.2.el6_3", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xulrunner-devel", rpm:"xulrunner-devel~17.0.3~1.0.2.el6_3", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"yelp", rpm:"yelp~2.28.1~17.el6_3", rls:"OracleLinux6"))) {
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
