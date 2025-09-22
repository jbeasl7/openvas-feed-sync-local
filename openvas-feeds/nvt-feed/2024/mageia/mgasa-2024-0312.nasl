# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2024.0312");
  script_cve_id("CVE-2024-6655");
  script_tag(name:"creation_date", value:"2024-09-26 04:11:43 +0000 (Thu, 26 Sep 2024)");
  script_version("2025-01-09T06:16:22+0000");
  script_tag(name:"last_modification", value:"2025-01-09 06:16:22 +0000 (Thu, 09 Jan 2025)");
  script_tag(name:"cvss_base", value:"6.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-16 15:15:12 +0000 (Tue, 16 Jul 2024)");

  script_name("Mageia: Security Advisory (MGASA-2024-0312)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2024-0312");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2024-0312.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=33409");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6899-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gtk+2.0, gtk+3.0' package(s) announced via the MGASA-2024-0312 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A flaw was found in the GTK library. Under certain conditions, it is
possible for a library to be injected into a GTK application from the
current working directory. (CVE-2024-6655)");

  script_tag(name:"affected", value:"'gtk+2.0, gtk+3.0' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"gtk+2.0", rpm:"gtk+2.0~2.24.33~5.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gtk+3.0", rpm:"gtk+3.0~3.24.38~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gtk-update-icon-cache", rpm:"gtk-update-icon-cache~3.24.38~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gail-devel", rpm:"lib64gail-devel~2.24.33~5.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gail18", rpm:"lib64gail18~2.24.33~5.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gail3.0-devel", rpm:"lib64gail3.0-devel~3.24.38~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gail3_0", rpm:"lib64gail3_0~3.24.38~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gtk+-x11-2.0_0", rpm:"lib64gtk+-x11-2.0_0~2.24.33~5.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gtk+2.0-devel", rpm:"lib64gtk+2.0-devel~2.24.33~5.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gtk+2.0_0", rpm:"lib64gtk+2.0_0~2.24.33~5.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gtk+3.0-devel", rpm:"lib64gtk+3.0-devel~3.24.38~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gtk+3_0", rpm:"lib64gtk+3_0~3.24.38~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gtk-gir2.0", rpm:"lib64gtk-gir2.0~2.24.33~5.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gtk-gir3.0", rpm:"lib64gtk-gir3.0~3.24.38~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgail-devel", rpm:"libgail-devel~2.24.33~5.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgail18", rpm:"libgail18~2.24.33~5.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgail3.0-devel", rpm:"libgail3.0-devel~3.24.38~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgail3_0", rpm:"libgail3_0~3.24.38~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgtk+-x11-2.0_0", rpm:"libgtk+-x11-2.0_0~2.24.33~5.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgtk+2.0-devel", rpm:"libgtk+2.0-devel~2.24.33~5.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgtk+2.0_0", rpm:"libgtk+2.0_0~2.24.33~5.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgtk+3.0-devel", rpm:"libgtk+3.0-devel~3.24.38~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgtk+3_0", rpm:"libgtk+3_0~3.24.38~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgtk-gir2.0", rpm:"libgtk-gir2.0~2.24.33~5.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgtk-gir3.0", rpm:"libgtk-gir3.0~3.24.38~1.1.mga9", rls:"MAGEIA9"))) {
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
