# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122282");
  script_cve_id("CVE-2010-0831", "CVE-2010-2322");
  script_tag(name:"creation_date", value:"2015-10-06 11:15:56 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");

  script_name("Oracle: Security Advisory (ELSA-2011-0025)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2011-0025");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2011-0025.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gcc' package(s) announced via the ELSA-2011-0025 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[4.1.2-50.el5]
- fix up fastjar directory traversal bugs (CVE-2010-0831)

[4.1.2-49.el5]
- fix ICE in set_uids_in_ptset (#605803)
- fix ICE in make_rtl_for_nonlocal_decl (#582682, #508735, #503565,
 PR c++/33094)
- don't build gcjwebplugin (#596097)
- fix IPP handling in libgcj (#578382)
- document -print-multi-os-directory (#529659, PR other/25507)
- fix ICE in output_die with function local types (#527510, PR debug/41063)
- speed up locale::locale() ctor if _S_global hasn't been changed
 (#635708, PR libstdc++/40088)");

  script_tag(name:"affected", value:"'gcc' package(s) on Oracle Linux 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"cpp", rpm:"cpp~4.1.2~50.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc", rpm:"gcc~4.1.2~50.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc-c++", rpm:"gcc-c++~4.1.2~50.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc-gfortran", rpm:"gcc-gfortran~4.1.2~50.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc-gnat", rpm:"gcc-gnat~4.1.2~50.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc-java", rpm:"gcc-java~4.1.2~50.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc-objc++", rpm:"gcc-objc++~4.1.2~50.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gcc-objc", rpm:"gcc-objc~4.1.2~50.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgcc", rpm:"libgcc~4.1.2~50.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgcj", rpm:"libgcj~4.1.2~50.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgcj-devel", rpm:"libgcj-devel~4.1.2~50.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgcj-src", rpm:"libgcj-src~4.1.2~50.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgfortran", rpm:"libgfortran~4.1.2~50.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgnat", rpm:"libgnat~4.1.2~50.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmudflap", rpm:"libmudflap~4.1.2~50.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmudflap-devel", rpm:"libmudflap-devel~4.1.2~50.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libobjc", rpm:"libobjc~4.1.2~50.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libstdc++", rpm:"libstdc++~4.1.2~50.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libstdc++-devel", rpm:"libstdc++-devel~4.1.2~50.el5", rls:"OracleLinux5"))) {
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
