# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2024.0219");
  script_cve_id("CVE-2024-37535");
  script_tag(name:"creation_date", value:"2024-06-17 04:12:21 +0000 (Mon, 17 Jun 2024)");
  script_version("2024-06-17T08:31:36+0000");
  script_tag(name:"last_modification", value:"2024-06-17 08:31:36 +0000 (Mon, 17 Jun 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mageia: Security Advisory (MGASA-2024-0219)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2024-0219");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2024-0219.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=33277");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2024/06/09/1");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2024/06/09/2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'vte' package(s) announced via the MGASA-2024-0219 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"GNOME VTE before 0.76.3 allows an attacker to cause a denial of service
(memory consumption) via a window resize escape sequence, a related
issue to CVE-2000-0476. (CVE-2024-37535)");

  script_tag(name:"affected", value:"'vte' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64vte-devel", rpm:"lib64vte-devel~0.72.1~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64vte-gir2.91", rpm:"lib64vte-gir2.91~0.72.1~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64vte-gir3.91", rpm:"lib64vte-gir3.91~0.72.1~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64vte-gtk4-devel", rpm:"lib64vte-gtk4-devel~0.72.1~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64vte-gtk4_2.91_0", rpm:"lib64vte-gtk4_2.91_0~0.72.1~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64vte2.91_0", rpm:"lib64vte2.91_0~0.72.1~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvte-devel", rpm:"libvte-devel~0.72.1~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvte-gir2.91", rpm:"libvte-gir2.91~0.72.1~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvte-gir3.91", rpm:"libvte-gir3.91~0.72.1~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvte-gtk4-devel", rpm:"libvte-gtk4-devel~0.72.1~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvte-gtk4_2.91_0", rpm:"libvte-gtk4_2.91_0~0.72.1~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvte2.91_0", rpm:"libvte2.91_0~0.72.1~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vte", rpm:"vte~0.72.1~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vte-glade", rpm:"vte-glade~0.72.1~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vte-gtk3", rpm:"vte-gtk3~0.72.1~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vte-gtk4", rpm:"vte-gtk4~0.72.1~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vte-profile", rpm:"vte-profile~0.72.1~1.1.mga9", rls:"MAGEIA9"))) {
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
