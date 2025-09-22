# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122568");
  script_cve_id("CVE-2008-2785", "CVE-2008-2933", "CVE-2008-3198");
  script_tag(name:"creation_date", value:"2015-10-08 11:48:15 +0000 (Thu, 08 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Oracle: Security Advisory (ELSA-2008-0597)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2008-0597");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2008-0597.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'devhelp, firefox, nspluginwrapper, xulrunner, yelp' package(s) announced via the ELSA-2008-0597 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"devhelp:

[0.12-18]
- Rebuild against xulrunner

firefox:

[3.0.1-1.0.1.el5]

- Replaced the RedHat prefs and bookmarks with Oracle prefs and bookmarks
- Add patch oracle-firefox-branding.patch
- Update firstrun URL

[3.0.1-1]
- Update to Firefox 3.0.1

xulrunner:

[1.9.0.1-1.0.1.el5]
- Added xulrunner-oracle-default-prefs.js

[1.9.0.1-1]
- Update to 1.9.0.1

yelp:

[2.16.0-20]
- rebuild against xulrunner");

  script_tag(name:"affected", value:"'devhelp, firefox, nspluginwrapper, xulrunner, yelp' package(s) on Oracle Linux 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"devhelp", rpm:"devhelp~0.12~18.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"devhelp-devel", rpm:"devhelp-devel~0.12~18.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox", rpm:"firefox~3.0.1~1.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nspluginwrapper", rpm:"nspluginwrapper~0.9.91.5~22.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xulrunner", rpm:"xulrunner~1.9.0.1~1.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xulrunner-devel", rpm:"xulrunner-devel~1.9.0.1~1.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xulrunner-devel-unstable", rpm:"xulrunner-devel-unstable~1.9.0.1~1.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"yelp", rpm:"yelp~2.16.0~20.el5", rls:"OracleLinux5"))) {
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
