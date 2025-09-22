# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122147");
  script_cve_id("CVE-2011-0862", "CVE-2011-0864", "CVE-2011-0865", "CVE-2011-0867", "CVE-2011-0868", "CVE-2011-0869", "CVE-2011-0871");
  script_tag(name:"creation_date", value:"2015-10-06 11:13:51 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Oracle: Security Advisory (ELSA-2011-0856)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2011-0856");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2011-0856.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java-1.6.0-openjdk' package(s) announced via the ELSA-2011-0856 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[1.6.0.0-1.39.1.9.8]
- Resolves: rhbz#709375
- Bumped to IcedTea6 1.9.8
- Copy fontconfig files to match names for current and next release
- RH706250, S6213702, CVE-2011-0872: (so) non-blocking sockets with TCP urgent
 disabled get still selected for read ops (win)
- RH706106, S6618658, CVE-2011-0865: Vulnerability in deserialization
- RH706111, S7012520, CVE-2011-0815: Heap overflow vulnerability in
 FileDialog.show()
- RH706139, S7013519, CVE-2011-0822, CVE-2011-0862: Integer overflows in 2D
 code
- RH706153, S7013969, CVE-2011-0867: NetworkInterface.toString can reveal
 bindings
- RH706234, S7013971, CVE-2011-0869: Vulnerability in SAAJ
- RH706239, S7016340, CVE-2011-0870: Vulnerability in SAAJ
- RH706241, S7016495, CVE-2011-0868: Crash in Java 2D transforming an image
 with scale close to zero
- RH706248, S7020198, CVE-2011-0871: ImageIcon creates Component with null acc
- RH706245, S7020373, CVE-2011-0864: JSR rewriting can overflow memory address
 size variables");

  script_tag(name:"affected", value:"'java-1.6.0-openjdk' package(s) on Oracle Linux 6.");

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

if(release == "OracleLinux6") {

  if(!isnull(res = isrpmvuln(pkg:"java-1.6.0-openjdk", rpm:"java-1.6.0-openjdk~1.6.0.0~1.39.1.9.8.el6_1", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.6.0-openjdk-demo", rpm:"java-1.6.0-openjdk-demo~1.6.0.0~1.39.1.9.8.el6_1", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.6.0-openjdk-devel", rpm:"java-1.6.0-openjdk-devel~1.6.0.0~1.39.1.9.8.el6_1", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.6.0-openjdk-javadoc", rpm:"java-1.6.0-openjdk-javadoc~1.6.0.0~1.39.1.9.8.el6_1", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.6.0-openjdk-src", rpm:"java-1.6.0-openjdk-src~1.6.0.0~1.39.1.9.8.el6_1", rls:"OracleLinux6"))) {
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
