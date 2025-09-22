# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122275");
  script_cve_id("CVE-2011-0020");
  script_tag(name:"creation_date", value:"2015-10-06 11:15:49 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");

  script_name("Oracle: Security Advisory (ELSA-2011-0180)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=(OracleLinux4|OracleLinux5|OracleLinux6)");

  script_xref(name:"Advisory-ID", value:"ELSA-2011-0180");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2011-0180.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'evolution28-pango, pango' package(s) announced via the ELSA-2011-0180 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[1.28.1-3.el6_0.3]
- Fix a division by zero found in testing

[1.28.1-3.el6_0.2]
- Use -fno-strict-aliasing for C++, too
- Escape macros in %changelog

[1.28.1-3.el6_0.1]
- Prevent heap corruption with malformed fonts. (CVE-2011-0020)
- Resolves: #671529");

  script_tag(name:"affected", value:"'evolution28-pango, pango' package(s) on Oracle Linux 4, Oracle Linux 5, Oracle Linux 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"evolution28-pango", rpm:"evolution28-pango~1.14.9~13.el4_10", rls:"OracleLinux4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"evolution28-pango-devel", rpm:"evolution28-pango-devel~1.14.9~13.el4_10", rls:"OracleLinux4"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"pango", rpm:"pango~1.14.9~8.0.1.el5_6.2", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pango-devel", rpm:"pango-devel~1.14.9~8.0.1.el5_6.2", rls:"OracleLinux5"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"pango", rpm:"pango~1.28.1~3.el6_0.3", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pango-devel", rpm:"pango-devel~1.28.1~3.el6_0.3", rls:"OracleLinux6"))) {
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
