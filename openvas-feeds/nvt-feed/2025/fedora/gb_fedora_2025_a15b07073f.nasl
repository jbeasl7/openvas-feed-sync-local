# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.97159807073102");
  script_cve_id("CVE-2024-0134", "CVE-2024-0135", "CVE-2024-0136", "CVE-2024-0137");
  script_tag(name:"creation_date", value:"2025-05-26 07:22:06 +0000 (Mon, 26 May 2025)");
  script_version("2025-05-27T05:40:44+0000");
  script_tag(name:"last_modification", value:"2025-05-27 05:40:44 +0000 (Tue, 27 May 2025)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:N/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-11-08 15:53:40 +0000 (Fri, 08 Nov 2024)");

  script_name("Fedora: Security Advisory (FEDORA-2025-a15b07073f)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC41");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-a15b07073f");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-a15b07073f");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2324084");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2342485");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2342489");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2342493");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'golang-github-nvidia-container-toolkit' package(s) announced via the FEDORA-2025-a15b07073f advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"* Update to 1.17.3
* Fixes CVE-2024-0134 or GHSA-7jm9-xpwx-v999
* Fixes CVE-2024-0135 or GHSA-9v84-cc9j-pxr6, CVE-2024-0136 or GHSA-vcfp-63cx-4h59, and CVE-2024-0137 or GHSA-frhw-w3wm-6cw4");

  script_tag(name:"affected", value:"'golang-github-nvidia-container-toolkit' package(s) on Fedora 41.");

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

if(release == "FC41") {

  if(!isnull(res = isrpmvuln(pkg:"golang-github-nvidia-container-toolkit", rpm:"golang-github-nvidia-container-toolkit~1.17.3~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-github-nvidia-container-toolkit-debuginfo", rpm:"golang-github-nvidia-container-toolkit-debuginfo~1.17.3~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-github-nvidia-container-toolkit-debugsource", rpm:"golang-github-nvidia-container-toolkit-debugsource~1.17.3~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-github-nvidia-container-toolkit-devel", rpm:"golang-github-nvidia-container-toolkit-devel~1.17.3~1.fc41", rls:"FC41"))) {
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
