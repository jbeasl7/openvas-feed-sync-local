# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122314");
  script_cve_id("CVE-2010-2806", "CVE-2010-2808", "CVE-2010-3054", "CVE-2010-3311");
  script_tag(name:"creation_date", value:"2015-10-06 11:16:37 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Oracle: Security Advisory (ELSA-2010-0737)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=(OracleLinux4|OracleLinux5)");

  script_xref(name:"Advisory-ID", value:"ELSA-2010-0737");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2010-0737.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'freetype' package(s) announced via the ELSA-2010-0737 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[2.2.1-28]
- Modify freetype-2.2.1-CVE-2010-3054.patch
- Resolves: #638142

[2.2.1-27]
- Add freetype-2.2.1-CVE-2010-2806.patch
 (Protect against negative string_size. Fix comparison.)
- Add freetype-2.2.1-CVE-2010-3311.patch
 (Don't seek behind end of stream.)
- Add freetype-2.2.1-CVE-2010-3054.patch
 (Protect against nested 'seac' calls.)
- Add freetype-2.2.1-CVE-2010-2808.patch
 (Check the total length of collected POST segments.)
- Resolves: #638142");

  script_tag(name:"affected", value:"'freetype' package(s) on Oracle Linux 4, Oracle Linux 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"freetype", rpm:"freetype~2.1.9~17.el4.8", rls:"OracleLinux4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freetype-demos", rpm:"freetype-demos~2.1.9~17.el4.8", rls:"OracleLinux4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freetype-devel", rpm:"freetype-devel~2.1.9~17.el4.8", rls:"OracleLinux4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freetype-utils", rpm:"freetype-utils~2.1.9~17.el4.8", rls:"OracleLinux4"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"freetype", rpm:"freetype~2.2.1~28.el5_5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freetype-demos", rpm:"freetype-demos~2.2.1~28.el5_5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freetype-devel", rpm:"freetype-devel~2.2.1~28.el5_5", rls:"OracleLinux5"))) {
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
