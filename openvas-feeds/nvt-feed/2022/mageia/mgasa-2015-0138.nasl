# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2015.0138");
  script_cve_id("CVE-2015-0250");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");

  script_name("Mageia: Security Advisory (MGASA-2015-0138)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA4");

  script_xref(name:"Advisory-ID", value:"MGASA-2015-0138");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0138.html");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2015/03/17/4");
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-2548-1/");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=15566");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'batik' package(s) announced via the MGASA-2015-0138 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated batik packages fix security vulnerability:

Nicolas Gregoire and Kevin Schaller discovered that Batik would load XML
external entities by default. If a user or automated system were tricked into
opening a specially crafted SVG file, an attacker could possibly obtain access
to arbitrary files or cause resource consumption (CVE-2015-0250).");

  script_tag(name:"affected", value:"'batik' package(s) on Mageia 4.");

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

if(release == "MAGEIA4") {

  if(!isnull(res = isrpmvuln(pkg:"batik", rpm:"batik~1.8~0.1.svn1230816.10.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"batik-demo", rpm:"batik-demo~1.8~0.1.svn1230816.10.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"batik-javadoc", rpm:"batik-javadoc~1.8~0.1.svn1230816.10.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"batik-rasterizer", rpm:"batik-rasterizer~1.8~0.1.svn1230816.10.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"batik-slideshow", rpm:"batik-slideshow~1.8~0.1.svn1230816.10.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"batik-squiggle", rpm:"batik-squiggle~1.8~0.1.svn1230816.10.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"batik-svgpp", rpm:"batik-svgpp~1.8~0.1.svn1230816.10.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"batik-ttf2svg", rpm:"batik-ttf2svg~1.8~0.1.svn1230816.10.mga4", rls:"MAGEIA4"))) {
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
