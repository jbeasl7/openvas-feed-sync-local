# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2026.102102768102810137");
  script_cve_id("CVE-2025-34297");
  script_tag(name:"creation_date", value:"2026-03-27 04:50:29 +0000 (Fri, 27 Mar 2026)");
  script_version("2026-03-27T06:06:36+0000");
  script_tag(name:"last_modification", value:"2026-03-27 06:06:36 +0000 (Fri, 27 Mar 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2026-ff768f8e37)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC42");

  script_xref(name:"Advisory-ID", value:"FEDORA-2026-ff768f8e37");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2026-ff768f8e37");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2418144");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2418147");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'vtk' package(s) announced via the FEDORA-2026-ff768f8e37 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Add patch to fix integer overflow on 32-bit in KissFFT (CVE-2025-34297)");

  script_tag(name:"affected", value:"'vtk' package(s) on Fedora 42.");

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

if(release == "FC42") {

  if(!isnull(res = isrpmvuln(pkg:"python3-vtk", rpm:"python3-vtk~9.2.6~38.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-vtk-debuginfo", rpm:"python3-vtk-debuginfo~9.2.6~38.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-vtk-mpich", rpm:"python3-vtk-mpich~9.2.6~38.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-vtk-mpich-debuginfo", rpm:"python3-vtk-mpich-debuginfo~9.2.6~38.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-vtk-openmpi", rpm:"python3-vtk-openmpi~9.2.6~38.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-vtk-openmpi-debuginfo", rpm:"python3-vtk-openmpi-debuginfo~9.2.6~38.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vtk", rpm:"vtk~9.2.6~38.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vtk-data", rpm:"vtk-data~9.2.6~38.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vtk-debuginfo", rpm:"vtk-debuginfo~9.2.6~38.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vtk-debugsource", rpm:"vtk-debugsource~9.2.6~38.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vtk-devel", rpm:"vtk-devel~9.2.6~38.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vtk-devel-debuginfo", rpm:"vtk-devel-debuginfo~9.2.6~38.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vtk-doc", rpm:"vtk-doc~9.2.6~38.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vtk-examples", rpm:"vtk-examples~9.2.6~38.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vtk-java", rpm:"vtk-java~9.2.6~38.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vtk-java-debuginfo", rpm:"vtk-java-debuginfo~9.2.6~38.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vtk-mpich", rpm:"vtk-mpich~9.2.6~38.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vtk-mpich-debuginfo", rpm:"vtk-mpich-debuginfo~9.2.6~38.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vtk-mpich-devel", rpm:"vtk-mpich-devel~9.2.6~38.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vtk-mpich-devel-debuginfo", rpm:"vtk-mpich-devel-debuginfo~9.2.6~38.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vtk-mpich-java", rpm:"vtk-mpich-java~9.2.6~38.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vtk-mpich-java-debuginfo", rpm:"vtk-mpich-java-debuginfo~9.2.6~38.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vtk-mpich-qt", rpm:"vtk-mpich-qt~9.2.6~38.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vtk-mpich-qt-debuginfo", rpm:"vtk-mpich-qt-debuginfo~9.2.6~38.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vtk-openmpi", rpm:"vtk-openmpi~9.2.6~38.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vtk-openmpi-debuginfo", rpm:"vtk-openmpi-debuginfo~9.2.6~38.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vtk-openmpi-devel", rpm:"vtk-openmpi-devel~9.2.6~38.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vtk-openmpi-devel-debuginfo", rpm:"vtk-openmpi-devel-debuginfo~9.2.6~38.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vtk-openmpi-java", rpm:"vtk-openmpi-java~9.2.6~38.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vtk-openmpi-java-debuginfo", rpm:"vtk-openmpi-java-debuginfo~9.2.6~38.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vtk-openmpi-qt", rpm:"vtk-openmpi-qt~9.2.6~38.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vtk-openmpi-qt-debuginfo", rpm:"vtk-openmpi-qt-debuginfo~9.2.6~38.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vtk-qt", rpm:"vtk-qt~9.2.6~38.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vtk-qt-debuginfo", rpm:"vtk-qt-debuginfo~9.2.6~38.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vtk-testing", rpm:"vtk-testing~9.2.6~38.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vtk-testing-debuginfo", rpm:"vtk-testing-debuginfo~9.2.6~38.fc42", rls:"FC42"))) {
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
