# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2024.0064");
  script_cve_id("CVE-2021-3610", "CVE-2023-3195", "CVE-2023-34151", "CVE-2023-3428");
  script_tag(name:"creation_date", value:"2024-03-18 04:11:54 +0000 (Mon, 18 Mar 2024)");
  script_version("2024-03-18T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-03-18 05:06:10 +0000 (Mon, 18 Mar 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-07 13:33:58 +0000 (Mon, 07 Mar 2022)");

  script_name("Mageia: Security Advisory (MGASA-2024-0064)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2024-0064");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2024-0064.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=32076");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6200-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'imagemagick' package(s) announced via the MGASA-2024-0064 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The updated packages fix security vulnerabilities:
A heap-based buffer overflow vulnerability was found in ImageMagick in
versions prior to 7.0.11-14 in ReadTIFFImage() in coders/tiff.c. This
issue is due to an incorrect setting of the pixel array size, which can
lead to a crash and segmentation fault. (CVE-2021-3610)
A stack-based buffer overflow issue was found in ImageMagick's
coders/tiff.c. This flaw allows an attacker to trick the user into
opening a specially crafted malicious tiff file, causing an application
to crash, resulting in a denial of service. (CVE-2023-3195)
A heap-based buffer overflow vulnerability was found in coders/tiff.c in
ImageMagick. This issue may allow a local attacker to trick the user
into opening a specially crafted file, resulting in an application crash
and denial of service. (CVE-2023-3428)
This security flaw ouccers as an undefined behaviors of casting double
to size_t in svg, mvg and other coders (recurring bugs of
CVE-2022-32546). (CVE-2023-34151)");

  script_tag(name:"affected", value:"'imagemagick' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"imagemagick", rpm:"imagemagick~7.1.1.29~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"imagemagick", rpm:"imagemagick~7.1.1.29~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"imagemagick-desktop", rpm:"imagemagick-desktop~7.1.1.29~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"imagemagick-desktop", rpm:"imagemagick-desktop~7.1.1.29~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"imagemagick-doc", rpm:"imagemagick-doc~7.1.1.29~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"imagemagick-doc", rpm:"imagemagick-doc~7.1.1.29~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64magick++-7Q16HDRI_5", rpm:"lib64magick++-7Q16HDRI_5~7.1.1.29~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64magick++-7Q16HDRI_5", rpm:"lib64magick++-7Q16HDRI_5~7.1.1.29~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64magick-7Q16HDRI_10", rpm:"lib64magick-7Q16HDRI_10~7.1.1.29~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64magick-7Q16HDRI_10", rpm:"lib64magick-7Q16HDRI_10~7.1.1.29~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64magick-devel", rpm:"lib64magick-devel~7.1.1.29~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64magick-devel", rpm:"lib64magick-devel~7.1.1.29~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmagick++-7Q16HDRI_5", rpm:"libmagick++-7Q16HDRI_5~7.1.1.29~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmagick++-7Q16HDRI_5", rpm:"libmagick++-7Q16HDRI_5~7.1.1.29~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmagick-7Q16HDRI_10", rpm:"libmagick-7Q16HDRI_10~7.1.1.29~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmagick-7Q16HDRI_10", rpm:"libmagick-7Q16HDRI_10~7.1.1.29~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmagick-devel", rpm:"libmagick-devel~7.1.1.29~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmagick-devel", rpm:"libmagick-devel~7.1.1.29~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Image-Magick", rpm:"perl-Image-Magick~7.1.1.29~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Image-Magick", rpm:"perl-Image-Magick~7.1.1.29~1.mga9.tainted", rls:"MAGEIA9"))) {
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
