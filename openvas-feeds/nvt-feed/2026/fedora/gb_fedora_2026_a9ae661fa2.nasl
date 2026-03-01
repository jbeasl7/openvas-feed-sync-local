# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2026.97997101661102972");
  script_cve_id("CVE-2026-22695", "CVE-2026-22801", "CVE-2026-25646");
  script_tag(name:"creation_date", value:"2026-02-17 04:39:36 +0000 (Tue, 17 Feb 2026)");
  script_version("2026-02-17T05:57:49+0000");
  script_tag(name:"last_modification", value:"2026-02-17 05:57:49 +0000 (Tue, 17 Feb 2026)");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-02-13 20:43:44 +0000 (Fri, 13 Feb 2026)");

  script_name("Fedora: Security Advisory (FEDORA-2026-a9ae661fa2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC43");

  script_xref(name:"Advisory-ID", value:"FEDORA-2026-a9ae661fa2");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2026-a9ae661fa2");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2437248");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2438669");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2438681");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libpng' package(s) announced via the FEDORA-2026-a9ae661fa2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Version 1.6.54 [January 12, 2026]
 Fixed CVE-2026-22695 (medium severity):
 Heap buffer over-read in `png_image_read_direct_scaled`.
 Fixed CVE-2026-22801 (medium severity):
 Integer truncation causing heap buffer over-read in `png_image_write_*`.

Version 1.6.55 [February 9, 2026]
 Fixed CVE-2026-25646 (high severity):
 Heap buffer overflow in `png_set_quantize`.");

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

  if(!isnull(res = isrpmvuln(pkg:"libpng", rpm:"libpng~1.6.55~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpng-debuginfo", rpm:"libpng-debuginfo~1.6.55~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpng-debugsource", rpm:"libpng-debugsource~1.6.55~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpng-devel", rpm:"libpng-devel~1.6.55~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpng-devel-debuginfo", rpm:"libpng-devel-debuginfo~1.6.55~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpng-static", rpm:"libpng-static~1.6.55~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpng-tools", rpm:"libpng-tools~1.6.55~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpng-tools-debuginfo", rpm:"libpng-tools-debuginfo~1.6.55~1.fc43", rls:"FC43"))) {
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
