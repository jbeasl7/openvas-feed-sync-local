# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123283");
  script_cve_id("CVE-2014-1574", "CVE-2014-1576", "CVE-2014-1577", "CVE-2014-1578", "CVE-2014-1581", "CVE-2014-1583");
  script_tag(name:"creation_date", value:"2015-10-06 11:01:43 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Oracle: Security Advisory (ELSA-2014-1635)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=(OracleLinux5|OracleLinux6|OracleLinux7)");

  script_xref(name:"Advisory-ID", value:"ELSA-2014-1635");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2014-1635.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox, xulrunner' package(s) announced via the ELSA-2014-1635 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"firefox
[31.2.0-3.0.1.el7_0]
- Add firefox-oracle-default-prefs.js and remove the corresponding Red Hat one

[31.2.0-3]
- Update to 31.2.0 ESR
- Fix for mozbz#1042889

[31.1.0-7]
- Enable WebM on all arches

xulrunner
[31.2.0-1.0.1]
- Replaced xulrunner-redhat-default-prefs.js with xulrunner-oracle-default-prefs.js
- Removed XULRUNNER_VERSION from SOURCE21

[31.2.0-1]
- Update to 31.2.0

[31.1.0-3]
- move /sdk/bin to xulrunner libdir

[31.1.0-2]
- Sync preferences with Firefox package

[31.1.0-1]
- Update to 31.1.0 ESR

[31.0-2]
- Fix header wrapper for aarch64

[31.0-1]
- Update to 31.0 ESR");

  script_tag(name:"affected", value:"'firefox, xulrunner' package(s) on Oracle Linux 5, Oracle Linux 6, Oracle Linux 7.");

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

  if(!isnull(res = isrpmvuln(pkg:"firefox", rpm:"firefox~31.2.0~3.0.1.el5_11", rls:"OracleLinux5"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"firefox", rpm:"firefox~31.2.0~3.0.1.el6_6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "OracleLinux7") {

  if(!isnull(res = isrpmvuln(pkg:"firefox", rpm:"firefox~31.2.0~3.0.1.el7_0", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xulrunner", rpm:"xulrunner~31.2.0~1.0.1.el7_0", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xulrunner-devel", rpm:"xulrunner-devel~31.2.0~1.0.1.el7_0", rls:"OracleLinux7"))) {
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
