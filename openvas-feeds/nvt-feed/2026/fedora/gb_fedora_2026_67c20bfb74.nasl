# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2026.679920981029874");
  script_cve_id("CVE-2026-25646", "CVE-2026-33416", "CVE-2026-33636");
  script_tag(name:"creation_date", value:"2026-04-13 05:05:57 +0000 (Mon, 13 Apr 2026)");
  script_version("2026-04-13T06:24:05+0000");
  script_tag(name:"last_modification", value:"2026-04-13 06:24:05 +0000 (Mon, 13 Apr 2026)");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-02-13 20:43:44 +0000 (Fri, 13 Feb 2026)");

  script_name("Fedora: Security Advisory (FEDORA-2026-67c20bfb74)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC43");

  script_xref(name:"Advisory-ID", value:"FEDORA-2026-67c20bfb74");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2026-67c20bfb74");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2452129");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2452155");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libpng' package(s) announced via the FEDORA-2026-67c20bfb74 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"1.6.56 is release fixes for the following two security vulnerabilities:

- CVE-2026-33416 (high severity): Use-after-free memory bug in the transparency and palette-handling code. Similar to its predecessor CVE-2026-25646, this latent bug has existed for 25 years. Both Halil Oktay and Ryo Shimada discovered it within days of one another.

- CVE-2026-33636 (high severity): Out-of-bounds read and write vulnerability in the ARM Neon palette-expansion code. This one was found and fixed by Taegu Ha and has existed since 1.6.36.

The images that trigger these bugs are valid. Users are encouraged to update immediately.");

  script_tag(name:"affected", value:"'libpng' package(s) on Fedora 43.");

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

if(release == "FC43") {

  if(!isnull(res = isrpmvuln(pkg:"libpng", rpm:"libpng~1.6.56~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpng-debuginfo", rpm:"libpng-debuginfo~1.6.56~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpng-debugsource", rpm:"libpng-debugsource~1.6.56~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpng-devel", rpm:"libpng-devel~1.6.56~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpng-devel-debuginfo", rpm:"libpng-devel-debuginfo~1.6.56~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpng-static", rpm:"libpng-static~1.6.56~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpng-tools", rpm:"libpng-tools~1.6.56~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpng-tools-debuginfo", rpm:"libpng-tools-debuginfo~1.6.56~1.fc43", rls:"FC43"))) {
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
