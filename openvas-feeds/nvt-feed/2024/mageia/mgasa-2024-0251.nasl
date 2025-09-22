# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2024.0251");
  script_cve_id("CVE-2024-28130", "CVE-2024-34508", "CVE-2024-34509");
  script_tag(name:"creation_date", value:"2024-07-04 04:11:34 +0000 (Thu, 04 Jul 2024)");
  script_version("2024-07-04T05:05:37+0000");
  script_tag(name:"last_modification", value:"2024-07-04 05:05:37 +0000 (Thu, 04 Jul 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-04-23 15:15:49 +0000 (Tue, 23 Apr 2024)");

  script_name("Mageia: Security Advisory (MGASA-2024-0251)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2024-0251");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2024-0251.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=33350");
  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2024/06/msg00022.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'dcmtk' package(s) announced via the MGASA-2024-0251 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities have benn fixed in DCMTK, a collection of
libraries and applications implementing large parts the DICOM standard
for medical images.
CVE-2021-41687
 Incorrect freeing of memory
CVE-2021-41688
 Incorrect freeing of memory
CVE-2021-41689
 NULL pointer dereference
CVE-2021-41690
 Incorrect freeing of memory
CVE-2022-2121
 NULL pointer dereference
CVE-2022-43272
 Memory leak in single process mode
CVE-2024-28130
 Segmentation faults due to incorrect typecast
CVE-2024-34508
 Segmentation fault via invalid DIMSE message
CVE-2024-34509
 Segmentation fault via invalid DIMSE message");

  script_tag(name:"affected", value:"'dcmtk' package(s) on Mageia 9.");

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

if(release == "MAGEIA9") {

  if(!isnull(res = isrpmvuln(pkg:"dcmtk", rpm:"dcmtk~3.6.7~4.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64dcmtk-devel", rpm:"lib64dcmtk-devel~3.6.7~4.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64dcmtk17", rpm:"lib64dcmtk17~3.6.7~4.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdcmtk-devel", rpm:"libdcmtk-devel~3.6.7~4.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdcmtk17", rpm:"libdcmtk17~3.6.7~4.1.mga9", rls:"MAGEIA9"))) {
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
