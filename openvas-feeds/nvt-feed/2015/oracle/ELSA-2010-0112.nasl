# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122392");
  script_cve_id("CVE-2009-1571", "CVE-2009-3988", "CVE-2010-0159", "CVE-2010-0160", "CVE-2010-0162", "CVE-2010-0167", "CVE-2010-0169", "CVE-2010-0171");
  script_tag(name:"creation_date", value:"2015-10-06 11:18:07 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Oracle: Security Advisory (ELSA-2010-0112)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=(OracleLinux4|OracleLinux5)");

  script_xref(name:"Advisory-ID", value:"ELSA-2010-0112");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2010-0112.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox, xulrunner' package(s) announced via the ELSA-2010-0112 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"firefox:

[3.0.18-1.0.1.el5_4]
- Update firstrun and homepage URLs in specfile
- Added patch oracle-firefox-branding.patch
- Added firefox-oracle-default-prefs.js/firefox-oracle-default-bookmarks.html
 and removed the corresponding RedHat ones

[3.0.18-1]
- Update to 3.0.18

xulrunner:

[1.9.0.18-1.0.1.el5_4]
- Added xulrunner-oracle-default-prefs.js and removed the corresponding
 RedHat one.

[1.9.0.18-1]
- Update to 1.9.0.18");

  script_tag(name:"affected", value:"'firefox, xulrunner' package(s) on Oracle Linux 4, Oracle Linux 5.");

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

if(release == "OracleLinux4") {

  if(!isnull(res = isrpmvuln(pkg:"firefox", rpm:"firefox~3.0.18~1.0.1.el4", rls:"OracleLinux4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "OracleLinux5") {

  if(!isnull(res = isrpmvuln(pkg:"firefox", rpm:"firefox~3.0.18~1.0.1.el5_4", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xulrunner", rpm:"xulrunner~1.9.0.18~1.0.1.el5_4", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xulrunner-devel", rpm:"xulrunner-devel~1.9.0.18~1.0.1.el5_4", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xulrunner-devel-unstable", rpm:"xulrunner-devel-unstable~1.9.0.18~1.0.1.el5_4", rls:"OracleLinux5"))) {
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
