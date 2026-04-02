# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2026.0060");
  script_cve_id("CVE-2026-25799");
  script_tag(name:"creation_date", value:"2026-03-20 04:39:13 +0000 (Fri, 20 Mar 2026)");
  script_version("2026-03-20T05:55:14+0000");
  script_tag(name:"last_modification", value:"2026-03-20 05:55:14 +0000 (Fri, 20 Mar 2026)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-02-24 18:44:52 +0000 (Tue, 24 Feb 2026)");

  script_name("Mageia: Security Advisory (MGASA-2026-0060)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2026-0060");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2026-0060.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=35199");
  script_xref(name:"URL", value:"https://github.com/ImageMagick/ImageMagick/security/advisories/GHSA-543g-8grm-9cw6");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/message/A4HXQ3URGVXBE42UAP5YCPCA63KZZPJ3/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'graphicsmagick, imagemagick' package(s) announced via the MGASA-2026-0060 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Division-by-Zero in YUV sampling factor validation leads to crash.
(CVE-2026-25799)");

  script_tag(name:"affected", value:"'graphicsmagick, imagemagick' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"graphicsmagick", rpm:"graphicsmagick~1.3.40~1.3.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphicsmagick", rpm:"graphicsmagick~1.3.40~1.3.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphicsmagick-doc", rpm:"graphicsmagick-doc~1.3.40~1.3.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphicsmagick-doc", rpm:"graphicsmagick-doc~1.3.40~1.3.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"imagemagick", rpm:"imagemagick~7.1.1.29~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"imagemagick", rpm:"imagemagick~7.1.1.29~1.2.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"imagemagick-desktop", rpm:"imagemagick-desktop~7.1.1.29~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"imagemagick-desktop", rpm:"imagemagick-desktop~7.1.1.29~1.2.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"imagemagick-doc", rpm:"imagemagick-doc~7.1.1.29~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"imagemagick-doc", rpm:"imagemagick-doc~7.1.1.29~1.2.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64graphicsmagick++12", rpm:"lib64graphicsmagick++12~1.3.40~1.3.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64graphicsmagick++12", rpm:"lib64graphicsmagick++12~1.3.40~1.3.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64graphicsmagick-devel", rpm:"lib64graphicsmagick-devel~1.3.40~1.3.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64graphicsmagick-devel", rpm:"lib64graphicsmagick-devel~1.3.40~1.3.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64graphicsmagick3", rpm:"lib64graphicsmagick3~1.3.40~1.3.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64graphicsmagick3", rpm:"lib64graphicsmagick3~1.3.40~1.3.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64graphicsmagickwand2", rpm:"lib64graphicsmagickwand2~1.3.40~1.3.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64graphicsmagickwand2", rpm:"lib64graphicsmagickwand2~1.3.40~1.3.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64magick++-7Q16HDRI_5", rpm:"lib64magick++-7Q16HDRI_5~7.1.1.29~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64magick++-7Q16HDRI_5", rpm:"lib64magick++-7Q16HDRI_5~7.1.1.29~1.2.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64magick-7Q16HDRI_10", rpm:"lib64magick-7Q16HDRI_10~7.1.1.29~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64magick-7Q16HDRI_10", rpm:"lib64magick-7Q16HDRI_10~7.1.1.29~1.2.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64magick-devel", rpm:"lib64magick-devel~7.1.1.29~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64magick-devel", rpm:"lib64magick-devel~7.1.1.29~1.2.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgraphicsmagick++12", rpm:"libgraphicsmagick++12~1.3.40~1.3.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgraphicsmagick++12", rpm:"libgraphicsmagick++12~1.3.40~1.3.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgraphicsmagick-devel", rpm:"libgraphicsmagick-devel~1.3.40~1.3.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgraphicsmagick-devel", rpm:"libgraphicsmagick-devel~1.3.40~1.3.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgraphicsmagick3", rpm:"libgraphicsmagick3~1.3.40~1.3.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgraphicsmagick3", rpm:"libgraphicsmagick3~1.3.40~1.3.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgraphicsmagickwand2", rpm:"libgraphicsmagickwand2~1.3.40~1.3.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgraphicsmagickwand2", rpm:"libgraphicsmagickwand2~1.3.40~1.3.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmagick++-7Q16HDRI_5", rpm:"libmagick++-7Q16HDRI_5~7.1.1.29~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmagick++-7Q16HDRI_5", rpm:"libmagick++-7Q16HDRI_5~7.1.1.29~1.2.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmagick-7Q16HDRI_10", rpm:"libmagick-7Q16HDRI_10~7.1.1.29~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmagick-7Q16HDRI_10", rpm:"libmagick-7Q16HDRI_10~7.1.1.29~1.2.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmagick-devel", rpm:"libmagick-devel~7.1.1.29~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmagick-devel", rpm:"libmagick-devel~7.1.1.29~1.2.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Graphics-Magick", rpm:"perl-Graphics-Magick~1.3.40~1.3.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Graphics-Magick", rpm:"perl-Graphics-Magick~1.3.40~1.3.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Image-Magick", rpm:"perl-Image-Magick~7.1.1.29~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Image-Magick", rpm:"perl-Image-Magick~7.1.1.29~1.2.mga9.tainted", rls:"MAGEIA9"))) {
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
