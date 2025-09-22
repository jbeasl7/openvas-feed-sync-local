# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.885354");
  script_cve_id("CVE-2023-34872");
  script_tag(name:"creation_date", value:"2023-12-01 02:19:30 +0000 (Fri, 01 Dec 2023)");
  script_version("2024-09-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-09-13 05:05:46 +0000 (Fri, 13 Sep 2024)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-08-04 18:43:26 +0000 (Fri, 04 Aug 2023)");

  script_name("Fedora: Security Advisory (FEDORA-2023-4285cca9bf)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC39");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-4285cca9bf");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2023-4285cca9bf");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2250822");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mingw-poppler' package(s) announced via the FEDORA-2023-4285cca9bf advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Backport fix for CVE-2023-34872.");

  script_tag(name:"affected", value:"'mingw-poppler' package(s) on Fedora 39.");

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

  if(!isnull(res = isrpmvuln(pkg:"mingw-poppler", rpm:"mingw-poppler~23.02.0~4.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-poppler", rpm:"mingw32-poppler~23.02.0~4.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-poppler-cpp", rpm:"mingw32-poppler-cpp~23.02.0~4.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-poppler-debuginfo", rpm:"mingw32-poppler-debuginfo~23.02.0~4.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-poppler-glib", rpm:"mingw32-poppler-glib~23.02.0~4.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-poppler-qt5", rpm:"mingw32-poppler-qt5~23.02.0~4.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-poppler-qt6", rpm:"mingw32-poppler-qt6~23.02.0~4.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-poppler", rpm:"mingw64-poppler~23.02.0~4.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-poppler-cpp", rpm:"mingw64-poppler-cpp~23.02.0~4.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-poppler-debuginfo", rpm:"mingw64-poppler-debuginfo~23.02.0~4.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-poppler-glib", rpm:"mingw64-poppler-glib~23.02.0~4.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-poppler-qt5", rpm:"mingw64-poppler-qt5~23.02.0~4.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-poppler-qt6", rpm:"mingw64-poppler-qt6~23.02.0~4.fc39", rls:"FC39"))) {
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
