# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2015.0471");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mageia: Security Advisory (MGASA-2015-0471)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2015-0471");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0471.html");
  script_xref(name:"URL", value:"http://trac.imagemagick.org/changeset/17846");
  script_xref(name:"URL", value:"http://trac.imagemagick.org/changeset/17855");
  script_xref(name:"URL", value:"http://www.imagemagick.org/discourse-server/viewtopic.php?f=3&t=26931");
  script_xref(name:"URL", value:"http://www.imagemagick.org/discourse-server/viewtopic.php?f=3&t=26932");
  script_xref(name:"URL", value:"http://www.imagemagick.org/discourse-server/viewtopic.php?f=3&t=26933");
  script_xref(name:"URL", value:"https://bugs.launchpad.net/ubuntu/+source/imagemagick/+bug/1448803");
  script_xref(name:"URL", value:"https://bugs.launchpad.net/ubuntu/+source/imagemagick/+bug/1459747");
  script_xref(name:"URL", value:"https://bugs.launchpad.net/ubuntu/+source/imagemagick/+bug/1490362");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=17318");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/pipermail/package-announce/2015-December/173409.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'imagemagick' package(s) announced via the MGASA-2015-0471 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated imagemagick packages fix security vulnerabilities:

This update fixes denial of service issues in miff, vicar, hdr, and pdb image
handling, a buffer overflow issue in icon handling, and double-free issues in
pict and tga image handling.");

  script_tag(name:"affected", value:"'imagemagick' package(s) on Mageia 5.");

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

if(release == "MAGEIA5") {

  if(!isnull(res = isrpmvuln(pkg:"imagemagick", rpm:"imagemagick~6.8.9.9~4.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"imagemagick-desktop", rpm:"imagemagick-desktop~6.8.9.9~4.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"imagemagick-doc", rpm:"imagemagick-doc~6.8.9.9~4.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64magick++-6Q16_5", rpm:"lib64magick++-6Q16_5~6.8.9.9~4.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64magick-6Q16_2", rpm:"lib64magick-6Q16_2~6.8.9.9~4.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64magick-devel", rpm:"lib64magick-devel~6.8.9.9~4.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmagick++-6Q16_5", rpm:"libmagick++-6Q16_5~6.8.9.9~4.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmagick-6Q16_2", rpm:"libmagick-6Q16_2~6.8.9.9~4.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmagick-devel", rpm:"libmagick-devel~6.8.9.9~4.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Image-Magick", rpm:"perl-Image-Magick~6.8.9.9~4.2.mga5", rls:"MAGEIA5"))) {
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
