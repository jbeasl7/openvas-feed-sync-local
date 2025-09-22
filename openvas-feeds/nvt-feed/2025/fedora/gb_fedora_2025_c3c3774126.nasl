# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.993993774126");
  script_cve_id("CVE-2025-23359");
  script_tag(name:"creation_date", value:"2025-05-02 04:04:57 +0000 (Fri, 02 May 2025)");
  script_version("2025-05-02T05:40:07+0000");
  script_tag(name:"last_modification", value:"2025-05-02 05:40:07 +0000 (Fri, 02 May 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2025-c3c3774126)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC40");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-c3c3774126");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-c3c3774126");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2345164");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'golang-github-nvidia-container-toolkit' package(s) announced via the FEDORA-2025-c3c3774126 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"* Update to 1.17.4
* Fixes CVE-2025-23359 or GHSA-4hmh-pm5p-9j7j");

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

  if(!isnull(res = isrpmvuln(pkg:"golang-github-nvidia-container-toolkit", rpm:"golang-github-nvidia-container-toolkit~1.17.4~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-github-nvidia-container-toolkit-debuginfo", rpm:"golang-github-nvidia-container-toolkit-debuginfo~1.17.4~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-github-nvidia-container-toolkit-debugsource", rpm:"golang-github-nvidia-container-toolkit-debugsource~1.17.4~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-github-nvidia-container-toolkit-devel", rpm:"golang-github-nvidia-container-toolkit-devel~1.17.4~1.fc40", rls:"FC40"))) {
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
