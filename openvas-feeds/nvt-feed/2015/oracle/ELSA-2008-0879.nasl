# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122554");
  script_cve_id("CVE-2008-3837", "CVE-2008-4058", "CVE-2008-4060", "CVE-2008-4061", "CVE-2008-4062", "CVE-2008-4063", "CVE-2008-4064", "CVE-2008-4065", "CVE-2008-4067", "CVE-2008-4068");
  script_tag(name:"creation_date", value:"2015-10-08 11:47:52 +0000 (Thu, 08 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Oracle: Security Advisory (ELSA-2008-0879)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2008-0879");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2008-0879.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'devhelp, firefox, nss, xulrunner, yelp' package(s) announced via the ELSA-2008-0879 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"devhelp:

[0.12-19]
- Rebuild against xulrunner

firefox:

[3.0.2-3.0.1.el5]
- Added firefox-oracle-default-prefs.js/firefox-oracle-default-bookmarks.html
- Removed the corresponding files of Red Hat.
- Added patch oracle-firefox-branding.patch
- Update firstrun URL

[3.0.2-3]
- Update to Firefox 3.0.2 build 6

[3.0.2-2]
- Update to Firefox 3.0.2 build 4

[3.0.2-1]
- Update to Firefox 3.0.2

[3.0.1-2]
- Fixed #447535 - RHEL 5.2 beta / upstream Firefox 3 beta 5
 autoConfig broken
- Fixed #445304 - HTML/index.html always redirects to en-US/index.html
 parallel compiles and -debuginfo packages

nss:

[3.12.1.1-1]
- Update to NSS_3_12_1_RC2

[3.12.1.0-1]
- Update to NSS_3_12_1_RC1

xulrunner:

[1.9.0.2-5.0.1]
- Added xulrunner-oracle-default-prefs.js
- Remove its corresponding of Red Hat.

[1.9.0.2-5]
- Update to 1.9.0.2 build 6

[1.9.0.2-4]
- Fixed firefox dependency (#445391)

[1.9.0.2-3]
- Update to 1.9.0.2 build 4

[1.9.0.2-2]
- Fixed gecko version

[1.9.0.2-1]
- Update to 1.9.0.2

[1.9.0.1-2]
- Updated provided gecko version

yelp:

[2.16.0-21]
- rebuild against xulrunner");

  script_tag(name:"affected", value:"'devhelp, firefox, nss, xulrunner, yelp' package(s) on Oracle Linux 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"devhelp", rpm:"devhelp~0.12~19.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"devhelp-devel", rpm:"devhelp-devel~0.12~19.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox", rpm:"firefox~3.0.2~3.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss", rpm:"nss~3.12.1.1~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss-devel", rpm:"nss-devel~3.12.1.1~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss-pkcs11-devel", rpm:"nss-pkcs11-devel~3.12.1.1~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss-tools", rpm:"nss-tools~3.12.1.1~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xulrunner", rpm:"xulrunner~1.9.0.2~5.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xulrunner-devel", rpm:"xulrunner-devel~1.9.0.2~5.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xulrunner-devel-unstable", rpm:"xulrunner-devel-unstable~1.9.0.2~5.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"yelp", rpm:"yelp~2.16.0~21.el5", rls:"OracleLinux5"))) {
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
