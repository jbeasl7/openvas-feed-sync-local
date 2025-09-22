# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2024.0068");
  script_cve_id("CVE-2022-38398", "CVE-2022-38648", "CVE-2022-40146", "CVE-2022-41704", "CVE-2022-42890");
  script_tag(name:"creation_date", value:"2024-03-18 04:11:54 +0000 (Mon, 18 Mar 2024)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-10-28 18:19:40 +0000 (Fri, 28 Oct 2022)");

  script_name("Mageia: Security Advisory (MGASA-2024-0068)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2024-0068");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2024-0068.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=30882");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6117-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2022/dsa-5264");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2022/09/22/2");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2022/09/22/3");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2022/09/22/4");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2022/10/25/2");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2022/10/25/3");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'batik' package(s) announced via the MGASA-2024-0068 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The updated packages fix security vulnerabilities:
Server-Side Request Forgery (SSRF) vulnerability in Batik of Apache XML
Graphics allows an attacker to load a url thru the jar protocol.
(CVE-2022-38398)
Server-Side Request Forgery (SSRF) vulnerability in Batik of Apache XML
Graphics allows an attacker to fetch external resources.
(CVE-2022-38648)
Server-Side Request Forgery (SSRF) vulnerability in Batik of Apache XML
Graphics allows an attacker to access files using a Jar url.
(CVE-2022-40146)
A vulnerability in Batik of Apache XML Graphics allows an attacker to
run untrusted Java code from an SVG. (CVE-2022-41704)
A vulnerability in Batik of Apache XML Graphics allows an attacker to
run Java code from untrusted SVG via JavaScript. (CVE-2022-42890)");

  script_tag(name:"affected", value:"'batik' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"batik", rpm:"batik~1.14~4.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"batik-css", rpm:"batik-css~1.14~4.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"batik-demo", rpm:"batik-demo~1.14~4.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"batik-javadoc", rpm:"batik-javadoc~1.14~4.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"batik-rasterizer", rpm:"batik-rasterizer~1.14~4.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"batik-slideshow", rpm:"batik-slideshow~1.14~4.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"batik-squiggle", rpm:"batik-squiggle~1.14~4.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"batik-svgpp", rpm:"batik-svgpp~1.14~4.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"batik-ttf2svg", rpm:"batik-ttf2svg~1.14~4.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"batik-util", rpm:"batik-util~1.14~4.1.mga9", rls:"MAGEIA9"))) {
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
