# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.229981005971997");
  script_cve_id("CVE-2024-27628", "CVE-2024-28130");
  script_tag(name:"creation_date", value:"2025-05-26 07:22:06 +0000 (Mon, 26 May 2025)");
  script_version("2025-05-27T05:40:43+0000");
  script_tag(name:"last_modification", value:"2025-05-27 05:40:43 +0000 (Tue, 27 May 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-04-23 15:15:49 +0000 (Tue, 23 Apr 2024)");

  script_name("Fedora: Security Advisory (FEDORA-2025-22c8d5a1c7)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC42");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-22c8d5a1c7");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-22c8d5a1c7");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2293952");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2293953");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2294757");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2294759");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2297944");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'InsightToolkit, OpenImageIO, ctk, dcmtk, gdcm' package(s) announced via the FEDORA-2025-22c8d5a1c7 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Update for dcmtk 3.6.9

Includes security fix for CVE-2024-27628, CVE-2024-28130");

  script_tag(name:"affected", value:"'InsightToolkit, OpenImageIO, ctk, dcmtk, gdcm' package(s) on Fedora 42.");

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

  if(!isnull(res = isrpmvuln(pkg:"InsightToolkit", rpm:"InsightToolkit~4.13.3~26.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"InsightToolkit-debuginfo", rpm:"InsightToolkit-debuginfo~4.13.3~26.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"InsightToolkit-debugsource", rpm:"InsightToolkit-debugsource~4.13.3~26.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"InsightToolkit-devel", rpm:"InsightToolkit-devel~4.13.3~26.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"InsightToolkit-doc", rpm:"InsightToolkit-doc~4.13.3~26.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"InsightToolkit-examples", rpm:"InsightToolkit-examples~4.13.3~26.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"InsightToolkit-vtk", rpm:"InsightToolkit-vtk~4.13.3~26.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"InsightToolkit-vtk-debuginfo", rpm:"InsightToolkit-vtk-debuginfo~4.13.3~26.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"InsightToolkit-vtk-devel", rpm:"InsightToolkit-vtk-devel~4.13.3~26.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"OpenImageIO", rpm:"OpenImageIO~2.5.16.0~6.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"OpenImageIO-debuginfo", rpm:"OpenImageIO-debuginfo~2.5.16.0~6.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"OpenImageIO-debugsource", rpm:"OpenImageIO-debugsource~2.5.16.0~6.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"OpenImageIO-devel", rpm:"OpenImageIO-devel~2.5.16.0~6.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"OpenImageIO-iv", rpm:"OpenImageIO-iv~2.5.16.0~6.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"OpenImageIO-iv-debuginfo", rpm:"OpenImageIO-iv-debuginfo~2.5.16.0~6.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"OpenImageIO-utils", rpm:"OpenImageIO-utils~2.5.16.0~6.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"OpenImageIO-utils-debuginfo", rpm:"OpenImageIO-utils-debuginfo~2.5.16.0~6.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ctk", rpm:"ctk~2023.07.13~5.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ctk-debuginfo", rpm:"ctk-debuginfo~2023.07.13~5.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ctk-debugsource", rpm:"ctk-debugsource~2023.07.13~5.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ctk-devel", rpm:"ctk-devel~2023.07.13~5.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ctk-devel-debuginfo", rpm:"ctk-devel-debuginfo~2023.07.13~5.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ctk-dicom", rpm:"ctk-dicom~2023.07.13~5.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ctk-dicom-debuginfo", rpm:"ctk-dicom-debuginfo~2023.07.13~5.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ctk-plugin-framework", rpm:"ctk-plugin-framework~2023.07.13~5.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ctk-plugin-framework-debuginfo", rpm:"ctk-plugin-framework-debuginfo~2023.07.13~5.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ctk-widgets", rpm:"ctk-widgets~2023.07.13~5.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ctk-widgets-debuginfo", rpm:"ctk-widgets-debuginfo~2023.07.13~5.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dcmtk", rpm:"dcmtk~3.6.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dcmtk-debuginfo", rpm:"dcmtk-debuginfo~3.6.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dcmtk-debugsource", rpm:"dcmtk-debugsource~3.6.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dcmtk-devel", rpm:"dcmtk-devel~3.6.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gdcm", rpm:"gdcm~3.0.24~8.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gdcm-applications", rpm:"gdcm-applications~3.0.24~8.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gdcm-applications-debuginfo", rpm:"gdcm-applications-debuginfo~3.0.24~8.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gdcm-debuginfo", rpm:"gdcm-debuginfo~3.0.24~8.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gdcm-debugsource", rpm:"gdcm-debugsource~3.0.24~8.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gdcm-devel", rpm:"gdcm-devel~3.0.24~8.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gdcm-doc", rpm:"gdcm-doc~3.0.24~8.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-gdcm", rpm:"python3-gdcm~3.0.24~8.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-gdcm-debuginfo", rpm:"python3-gdcm-debuginfo~3.0.24~8.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-openimageio", rpm:"python3-openimageio~2.5.16.0~6.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-openimageio-debuginfo", rpm:"python3-openimageio-debuginfo~2.5.16.0~6.fc42", rls:"FC42"))) {
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
