# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2014.0004");
  script_cve_id("CVE-2013-1881");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");

  script_name("Mageia: Security Advisory (MGASA-2014-0004)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA3");

  script_xref(name:"Advisory-ID", value:"MGASA-2014-0004");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2014-0004.html");
  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-updates/2013-11/msg00114.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=11853");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gtk+3.0, librsvg' package(s) announced via the MGASA-2014-0004 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"librsvg before version 2.39.0 allows remote attackers to read arbitrary files
via an XML document containing an external entity declaration in conjunction
with an entity reference (CVE-2013-1881).

gtk+3.0 has been patched to cope with the changes in SVG loading due to the
fix in librsvg.");

  script_tag(name:"affected", value:"'gtk+3.0, librsvg' package(s) on Mageia 3.");

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

if(release == "MAGEIA3") {

  if(!isnull(res = isrpmvuln(pkg:"gtk+3.0", rpm:"gtk+3.0~3.6.4~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gail3.0-devel", rpm:"lib64gail3.0-devel~3.6.4~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gail3_0", rpm:"lib64gail3_0~3.6.4~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gtk+3.0-devel", rpm:"lib64gtk+3.0-devel~3.6.4~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gtk+3_0", rpm:"lib64gtk+3_0~3.6.4~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gtk-gir3.0", rpm:"lib64gtk-gir3.0~3.6.4~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64rsvg-gir2.0", rpm:"lib64rsvg-gir2.0~2.36.4~2.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64rsvg2-devel", rpm:"lib64rsvg2-devel~2.36.4~2.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64rsvg2_2", rpm:"lib64rsvg2_2~2.36.4~2.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgail3.0-devel", rpm:"libgail3.0-devel~3.6.4~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgail3_0", rpm:"libgail3_0~3.6.4~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgtk+3.0-devel", rpm:"libgtk+3.0-devel~3.6.4~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgtk+3_0", rpm:"libgtk+3_0~3.6.4~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgtk-gir3.0", rpm:"libgtk-gir3.0~3.6.4~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librsvg", rpm:"librsvg~2.36.4~2.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librsvg-gir2.0", rpm:"librsvg-gir2.0~2.36.4~2.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librsvg2-devel", rpm:"librsvg2-devel~2.36.4~2.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librsvg2_2", rpm:"librsvg2_2~2.36.4~2.1.mga3", rls:"MAGEIA3"))) {
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
