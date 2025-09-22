# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.887359");
  script_cve_id("CVE-2024-39936");
  script_tag(name:"creation_date", value:"2024-08-08 04:04:24 +0000 (Thu, 08 Aug 2024)");
  script_version("2024-09-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-09-13 05:05:46 +0000 (Fri, 13 Sep 2024)");
  script_tag(name:"cvss_base", value:"5.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-08 16:41:50 +0000 (Mon, 08 Jul 2024)");

  script_name("Fedora: Security Advisory (FEDORA-2024-81c4b76a71)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC40");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-81c4b76a71");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-81c4b76a71");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2295884");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mingw-qt6-qtbase' package(s) announced via the FEDORA-2024-81c4b76a71 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Apply fix for CVE-2024-39936");

  script_tag(name:"affected", value:"'mingw-qt6-qtbase' package(s) on Fedora 40.");

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

if(release == "FC40") {

  if(!isnull(res = isrpmvuln(pkg:"mingw-qt6-qtbase", rpm:"mingw-qt6-qtbase~6.7.2~3.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-qt6-qtbase", rpm:"mingw32-qt6-qtbase~6.7.2~3.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-qt6-qtbase-debuginfo", rpm:"mingw32-qt6-qtbase-debuginfo~6.7.2~3.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-qt6-qtbase", rpm:"mingw64-qt6-qtbase~6.7.2~3.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-qt6-qtbase-debuginfo", rpm:"mingw64-qt6-qtbase-debuginfo~6.7.2~3.fc40", rls:"FC40"))) {
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
