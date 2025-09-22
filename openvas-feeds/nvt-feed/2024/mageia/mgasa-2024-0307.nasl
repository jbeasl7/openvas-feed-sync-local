# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2024.0307");
  script_cve_id("CVE-2024-20505", "CVE-2024-20506");
  script_tag(name:"creation_date", value:"2024-09-17 04:12:27 +0000 (Tue, 17 Sep 2024)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-09-12 17:28:47 +0000 (Thu, 12 Sep 2024)");

  script_name("Mageia: Security Advisory (MGASA-2024-0307)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2024-0307");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2024-0307.html");
  script_xref(name:"URL", value:"https://blog.clamav.net/2024/09/clamav-141-132-107-and-010312-security.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=33561");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'clamav' package(s) announced via the MGASA-2024-0307 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Fixed a possible out-of-bounds read bug in the PDF file parser that
could cause a denial-of-service (DoS) condition. (CVE-2024-20505)
Changed the logging module to disable following symlinks on Linux and
Unix systems so as to prevent an attacker with existing access to the
'clamd' or 'freshclam' services from using a symlink to corrupt system
files. (CVE-2024-20506)");

  script_tag(name:"affected", value:"'clamav' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"clamav", rpm:"clamav~1.0.7~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"clamav-db", rpm:"clamav-db~1.0.7~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"clamav-milter", rpm:"clamav-milter~1.0.7~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"clamd", rpm:"clamd~1.0.7~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64clamav-devel", rpm:"lib64clamav-devel~1.0.7~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64clamav11", rpm:"lib64clamav11~1.0.7~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libclamav-devel", rpm:"libclamav-devel~1.0.7~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libclamav11", rpm:"libclamav11~1.0.7~1.mga9", rls:"MAGEIA9"))) {
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
