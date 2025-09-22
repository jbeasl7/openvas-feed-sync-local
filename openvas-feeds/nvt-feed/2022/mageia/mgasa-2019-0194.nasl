# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2019.0194");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mageia: Security Advisory (MGASA-2019-0194)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA6");

  script_xref(name:"Advisory-ID", value:"MGASA-2019-0194");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2019-0194.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=24966");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2019/06/15/9");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'graphicsmagick' package(s) announced via the MGASA-2019-0194 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"GraphicsMagick 1.3.32 is now released, fixing another 52 additional
issues detected by oss-fuzz.

Of special mention is a bug reported to us by 'Battle Furry' via our
security mail alias. This bug (was considered to be a 'feature')
allows including file text as rendered text on a graphic image, or as
text hidden in metadata, by using a file referred to with '@...ename'
syntax where text to be rendered normally appears. This issue was
inherited from ImageMagick 5.5.2 and it even appears in ImageMagick
4.2.9.

It has been determined that the SVG and WMF formats may be used to
supply this '@...ename' syntax, resulting in rendered text on a
graphic image, or as text hidden in metadata (e.g. the image comment).
Furthermore, it may be that other applications and web sites accept
text to be rendered on behalf of users and that this issue could allow
untrusted users to receive content considered to be secure and private
(e.g. private keys or passwords).");

  script_tag(name:"affected", value:"'graphicsmagick' package(s) on Mageia 6.");

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

if(release == "MAGEIA6") {

  if(!isnull(res = isrpmvuln(pkg:"graphicsmagick", rpm:"graphicsmagick~1.3.32~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphicsmagick-doc", rpm:"graphicsmagick-doc~1.3.32~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64graphicsmagick++12", rpm:"lib64graphicsmagick++12~1.3.32~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64graphicsmagick-devel", rpm:"lib64graphicsmagick-devel~1.3.32~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64graphicsmagick3", rpm:"lib64graphicsmagick3~1.3.32~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64graphicsmagickwand2", rpm:"lib64graphicsmagickwand2~1.3.32~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgraphicsmagick++12", rpm:"libgraphicsmagick++12~1.3.32~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgraphicsmagick-devel", rpm:"libgraphicsmagick-devel~1.3.32~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgraphicsmagick3", rpm:"libgraphicsmagick3~1.3.32~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgraphicsmagickwand2", rpm:"libgraphicsmagickwand2~1.3.32~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Graphics-Magick", rpm:"perl-Graphics-Magick~1.3.32~1.mga6", rls:"MAGEIA6"))) {
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
