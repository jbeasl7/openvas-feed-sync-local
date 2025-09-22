# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833773");
  script_version("2025-03-11T05:38:16+0000");
  script_cve_id("CVE-2022-2119", "CVE-2022-2120", "CVE-2022-2121", "CVE-2022-43272");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-03-11 05:38:16 +0000 (Tue, 11 Mar 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-07-05 17:26:48 +0000 (Tue, 05 Jul 2022)");
  script_tag(name:"creation_date", value:"2024-03-04 07:36:57 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for dcmtk (openSUSE-SU-2023:0108-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSEBackportsSLE-15-SP4");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2023:0108-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/MKL5XGJX4U2PD4XAVAZG2YAU2LYKLQIH");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'dcmtk'
  package(s) announced via the openSUSE-SU-2023:0108-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for dcmtk fixes the following issues:

  - CVE-2022-43272: Fixed memory leak via the T_ASC_Association object
       (boo#1206070)

  - Update to 3.6.7 (boo#1208639, boo#1208638, boo#1208637, CVE-2022-2121,
       CVE-2022-2120, CVE-2022-2119)

  - CVE-2022-2121: Fixed possible DoS via NULL pointer dereference

  - CVE-2022-2120: Fixed relative path traversal vulnerability

  - CVE-2022-2119: Fixed path traversal vulnerability

       See DOCS/CHANGES.367 for the full list of changes

  * Updated code definitions for DICOM 2022b

  * Fixed possible NULL pointer dereference");

  script_tag(name:"affected", value:"'dcmtk' package(s) on openSUSE Backports SLE-15-SP4.");

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

if(release == "openSUSEBackportsSLE-15-SP4") {

  if(!isnull(res = isrpmvuln(pkg:"dcmtk", rpm:"dcmtk~3.6.7~bp154.2.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dcmtk-devel", rpm:"dcmtk-devel~3.6.7~bp154.2.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdcmtk17", rpm:"libdcmtk17~3.6.7~bp154.2.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dcmtk", rpm:"dcmtk~3.6.7~bp154.2.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dcmtk-devel", rpm:"dcmtk-devel~3.6.7~bp154.2.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdcmtk17", rpm:"libdcmtk17~3.6.7~bp154.2.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
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