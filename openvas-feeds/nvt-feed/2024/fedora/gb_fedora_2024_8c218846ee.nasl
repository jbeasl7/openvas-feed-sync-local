# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2024.899218846101101");
  script_cve_id("CVE-2024-0132", "CVE-2024-0133");
  script_tag(name:"creation_date", value:"2024-11-13 04:08:19 +0000 (Wed, 13 Nov 2024)");
  script_version("2024-11-14T05:05:31+0000");
  script_tag(name:"last_modification", value:"2024-11-14 05:05:31 +0000 (Thu, 14 Nov 2024)");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-10-02 14:45:36 +0000 (Wed, 02 Oct 2024)");

  script_name("Fedora: Security Advisory (FEDORA-2024-8c218846ee)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC40");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-8c218846ee");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-8c218846ee");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'golang-github-nvidia-container-toolkit' package(s) announced via the FEDORA-2024-8c218846ee advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"* Update to 1.16.2

* Fixes CVE-2024-0132 or GHSA-mjjw-553x-87pq, and CVE-2024-0133 or GHSA-f748-7hpg-88ch");

  script_tag(name:"affected", value:"'golang-github-nvidia-container-toolkit' package(s) on Fedora 40.");

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

  if(!isnull(res = isrpmvuln(pkg:"golang-github-nvidia-container-toolkit", rpm:"golang-github-nvidia-container-toolkit~1.16.2~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-github-nvidia-container-toolkit-debuginfo", rpm:"golang-github-nvidia-container-toolkit-debuginfo~1.16.2~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-github-nvidia-container-toolkit-debugsource", rpm:"golang-github-nvidia-container-toolkit-debugsource~1.16.2~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-github-nvidia-container-toolkit-devel", rpm:"golang-github-nvidia-container-toolkit-devel~1.16.2~1.fc40", rls:"FC40"))) {
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
