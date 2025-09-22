# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.886310");
  script_cve_id("CVE-2023-47995", "CVE-2023-47997");
  script_tag(name:"creation_date", value:"2024-03-25 09:37:25 +0000 (Mon, 25 Mar 2024)");
  script_version("2024-09-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-09-13 05:05:46 +0000 (Fri, 13 Sep 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-16 20:58:57 +0000 (Tue, 16 Jan 2024)");

  script_name("Fedora: Security Advisory (FEDORA-2024-c0b61ab46b)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC39");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-c0b61ab46b");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-c0b61ab46b");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2257661");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2257665");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2257666");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2257670");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'freeimage, mingw-freeimage' package(s) announced via the FEDORA-2024-c0b61ab46b advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Add downstream fixes for CVE-2023-47995 and CVE-2023-47997.");

  script_tag(name:"affected", value:"'freeimage, mingw-freeimage' package(s) on Fedora 39.");

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

if(release == "FC39") {

  if(!isnull(res = isrpmvuln(pkg:"freeimage", rpm:"freeimage~3.19.0~0.23.svn1909.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeimage-debuginfo", rpm:"freeimage-debuginfo~3.19.0~0.23.svn1909.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeimage-debugsource", rpm:"freeimage-debugsource~3.19.0~0.23.svn1909.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeimage-devel", rpm:"freeimage-devel~3.19.0~0.23.svn1909.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeimage-plus", rpm:"freeimage-plus~3.19.0~0.23.svn1909.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeimage-plus-debuginfo", rpm:"freeimage-plus-debuginfo~3.19.0~0.23.svn1909.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeimage-plus-devel", rpm:"freeimage-plus-devel~3.19.0~0.23.svn1909.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw-freeimage", rpm:"mingw-freeimage~3.19.0~0.20.svn1909.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-freeimage", rpm:"mingw32-freeimage~3.19.0~0.20.svn1909.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-freeimage-debuginfo", rpm:"mingw32-freeimage-debuginfo~3.19.0~0.20.svn1909.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-freeimage-static", rpm:"mingw32-freeimage-static~3.19.0~0.20.svn1909.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-freeimage", rpm:"mingw64-freeimage~3.19.0~0.20.svn1909.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-freeimage-debuginfo", rpm:"mingw64-freeimage-debuginfo~3.19.0~0.20.svn1909.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-freeimage-static", rpm:"mingw64-freeimage-static~3.19.0~0.20.svn1909.fc39", rls:"FC39"))) {
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
