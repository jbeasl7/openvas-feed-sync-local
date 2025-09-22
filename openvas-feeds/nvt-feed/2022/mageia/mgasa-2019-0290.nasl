# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2019.0290");
  script_cve_id("CVE-2019-11471");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-02-02T05:06:09+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:09 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-04-24 14:27:02 +0000 (Wed, 24 Apr 2019)");

  script_name("Mageia: Security Advisory (MGASA-2019-0290)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2019-0290");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2019-0290.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=25319");
  script_xref(name:"URL", value:"https://github.com/strukturag/libheif/releases/tag/v1.4.1");
  script_xref(name:"URL", value:"https://imagemagick.org/script/changelog.php");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'imagemagick, libheif' package(s) announced via the MGASA-2019-0290 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"libheif 1.4.0 has a use-after-free in heif::HeifContext::Image::
set_alpha_channel in heif_context.h because heif_context.cc mishandles
references to non-existing alpha images (CVE-2019-11471).

Also, imagemagick has been updated to 7.0.8.62 to fix various bugs.");

  script_tag(name:"affected", value:"'imagemagick, libheif' package(s) on Mageia 7.");

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

if(release == "MAGEIA7") {

  if(!isnull(res = isrpmvuln(pkg:"imagemagick", rpm:"imagemagick~7.0.8.62~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"imagemagick", rpm:"imagemagick~7.0.8.62~1.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"imagemagick-desktop", rpm:"imagemagick-desktop~7.0.8.62~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"imagemagick-desktop", rpm:"imagemagick-desktop~7.0.8.62~1.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"imagemagick-doc", rpm:"imagemagick-doc~7.0.8.62~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"imagemagick-doc", rpm:"imagemagick-doc~7.0.8.62~1.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64heif-devel", rpm:"lib64heif-devel~1.4.1~1.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64heif1", rpm:"lib64heif1~1.4.1~1.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64magick++-7Q16HDRI_4", rpm:"lib64magick++-7Q16HDRI_4~7.0.8.62~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64magick++-7Q16HDRI_4", rpm:"lib64magick++-7Q16HDRI_4~7.0.8.62~1.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64magick-7Q16HDRI_6", rpm:"lib64magick-7Q16HDRI_6~7.0.8.62~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64magick-7Q16HDRI_6", rpm:"lib64magick-7Q16HDRI_6~7.0.8.62~1.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64magick-devel", rpm:"lib64magick-devel~7.0.8.62~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64magick-devel", rpm:"lib64magick-devel~7.0.8.62~1.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libheif", rpm:"libheif~1.4.1~1.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libheif-devel", rpm:"libheif-devel~1.4.1~1.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libheif1", rpm:"libheif1~1.4.1~1.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmagick++-7Q16HDRI_4", rpm:"libmagick++-7Q16HDRI_4~7.0.8.62~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmagick++-7Q16HDRI_4", rpm:"libmagick++-7Q16HDRI_4~7.0.8.62~1.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmagick-7Q16HDRI_6", rpm:"libmagick-7Q16HDRI_6~7.0.8.62~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmagick-7Q16HDRI_6", rpm:"libmagick-7Q16HDRI_6~7.0.8.62~1.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmagick-devel", rpm:"libmagick-devel~7.0.8.62~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmagick-devel", rpm:"libmagick-devel~7.0.8.62~1.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Image-Magick", rpm:"perl-Image-Magick~7.0.8.62~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Image-Magick", rpm:"perl-Image-Magick~7.0.8.62~1.mga7.tainted", rls:"MAGEIA7"))) {
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
