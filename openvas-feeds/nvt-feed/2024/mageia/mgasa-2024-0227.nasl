# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2024.0227");
  script_cve_id("CVE-2024-35235");
  script_tag(name:"creation_date", value:"2024-06-18 04:11:36 +0000 (Tue, 18 Jun 2024)");
  script_version("2024-06-18T05:05:55+0000");
  script_tag(name:"last_modification", value:"2024-06-18 05:05:55 +0000 (Tue, 18 Jun 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mageia: Security Advisory (MGASA-2024-0227)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2024-0227");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2024-0227.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=33293");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2024/06/11/1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cups' package(s) announced via the MGASA-2024-0227 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"When starting the cupsd server with a Listen configuration item pointing
to a symbolic link, the cupsd process can be caused to perform an
arbitrary chmod of the provided argument, providing world-writable
access to the target.");

  script_tag(name:"affected", value:"'cups' package(s) on Mageia 9.");

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

if(release == "MAGEIA9") {

  if(!isnull(res = isrpmvuln(pkg:"cups", rpm:"cups~2.4.6~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cups-common", rpm:"cups-common~2.4.6~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cups-filesystem", rpm:"cups-filesystem~2.4.6~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cups-printerapp", rpm:"cups-printerapp~2.4.6~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64cups2", rpm:"lib64cups2~2.4.6~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64cups2-devel", rpm:"lib64cups2-devel~2.4.6~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcups2", rpm:"libcups2~2.4.6~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcups2-devel", rpm:"libcups2-devel~2.4.6~1.2.mga9", rls:"MAGEIA9"))) {
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
