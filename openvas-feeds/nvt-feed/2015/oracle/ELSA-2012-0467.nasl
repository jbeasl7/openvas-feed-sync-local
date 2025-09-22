# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123941");
  script_cve_id("CVE-2012-1126", "CVE-2012-1127", "CVE-2012-1130", "CVE-2012-1131", "CVE-2012-1132", "CVE-2012-1134", "CVE-2012-1136", "CVE-2012-1137", "CVE-2012-1139", "CVE-2012-1140", "CVE-2012-1141", "CVE-2012-1142", "CVE-2012-1143", "CVE-2012-1144");
  script_tag(name:"creation_date", value:"2015-10-06 11:10:36 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Oracle: Security Advisory (ELSA-2012-0467)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=(OracleLinux5|OracleLinux6)");

  script_xref(name:"Advisory-ID", value:"ELSA-2012-0467");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2012-0467.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'freetype' package(s) announced via the ELSA-2012-0467 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[2.3.11-6.el6_2.9]
- Fix CVE-2012-{1126, 1127, 1130, 1131, 1132, 1134, 1136,
 1137, 1139, 1140, 1141, 1142, 1143, 1144}
- Properly initialize array 'result' in
 FT_Outline_Get_Orientation()
- Check bytes per row for overflow in _bdf_parse_glyphs()
- Resolves: #806268");

  script_tag(name:"affected", value:"'freetype' package(s) on Oracle Linux 5, Oracle Linux 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"freetype", rpm:"freetype~2.2.1~31.el5_8.1", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freetype-demos", rpm:"freetype-demos~2.2.1~31.el5_8.1", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freetype-devel", rpm:"freetype-devel~2.2.1~31.el5_8.1", rls:"OracleLinux5"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"freetype", rpm:"freetype~2.3.11~6.el6_2.9", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freetype-demos", rpm:"freetype-demos~2.3.11~6.el6_2.9", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freetype-devel", rpm:"freetype-devel~2.3.11~6.el6_2.9", rls:"OracleLinux6"))) {
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
