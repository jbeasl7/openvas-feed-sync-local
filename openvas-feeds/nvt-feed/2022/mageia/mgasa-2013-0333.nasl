# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2013.0333");
  script_cve_id("CVE-2013-6629", "CVE-2013-6630");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mageia: Security Advisory (MGASA-2013-0333)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(2|3)");

  script_xref(name:"Advisory-ID", value:"MGASA-2013-0333");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2013-0333.html");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.com/2013/11/stable-channel-update.html");
  script_xref(name:"URL", value:"http://permalink.gmane.org/gmane.comp.security.full-disclosure/90919");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=11658");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libjpeg' package(s) announced via the MGASA-2013-0333 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated libjpeg packages fix security vulnerabilities:

libjpeg 6b and libjpeg-turbo will use uninitialized memory when decoding
images with missing SOS data for the luminance component (Y) in presence of
valid chroma data (Cr, Cb) (CVE-2013-6629).

libjpeg-turbo will use uninitialized memory when handling Huffman tables
(CVE-2013-6630).");

  script_tag(name:"affected", value:"'libjpeg' package(s) on Mageia 2, Mageia 3.");

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

if(release == "MAGEIA2") {

  if(!isnull(res = isrpmvuln(pkg:"jpeg-progs", rpm:"jpeg-progs~1.2.0~4.2.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64jpeg-devel", rpm:"lib64jpeg-devel~1.2.0~4.2.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64jpeg-static-devel", rpm:"lib64jpeg-static-devel~1.2.0~4.2.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64jpeg62", rpm:"lib64jpeg62~1.2.0~4.2.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64jpeg8", rpm:"lib64jpeg8~1.2.0~4.2.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjpeg", rpm:"libjpeg~1.2.0~4.2.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjpeg-devel", rpm:"libjpeg-devel~1.2.0~4.2.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjpeg-static-devel", rpm:"libjpeg-static-devel~1.2.0~4.2.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjpeg62", rpm:"libjpeg62~1.2.0~4.2.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjpeg8", rpm:"libjpeg8~1.2.0~4.2.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MAGEIA3") {

  if(!isnull(res = isrpmvuln(pkg:"jpeg-progs", rpm:"jpeg-progs~1.2.1~4.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64jpeg-devel", rpm:"lib64jpeg-devel~1.2.1~4.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64jpeg-static-devel", rpm:"lib64jpeg-static-devel~1.2.1~4.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64jpeg62", rpm:"lib64jpeg62~1.2.1~4.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64jpeg8", rpm:"lib64jpeg8~1.2.1~4.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64turbojpeg", rpm:"lib64turbojpeg~1.2.1~4.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjpeg", rpm:"libjpeg~1.2.1~4.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjpeg-devel", rpm:"libjpeg-devel~1.2.1~4.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjpeg-static-devel", rpm:"libjpeg-static-devel~1.2.1~4.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjpeg62", rpm:"libjpeg62~1.2.1~4.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjpeg8", rpm:"libjpeg8~1.2.1~4.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libturbojpeg", rpm:"libturbojpeg~1.2.1~4.1.mga3", rls:"MAGEIA3"))) {
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
