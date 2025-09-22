# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2025.0202");
  script_cve_id("CVE-2024-48877", "CVE-2024-52035", "CVE-2024-54028");
  script_tag(name:"creation_date", value:"2025-07-07 04:18:08 +0000 (Mon, 07 Jul 2025)");
  script_version("2025-07-07T05:42:05+0000");
  script_tag(name:"last_modification", value:"2025-07-07 05:42:05 +0000 (Mon, 07 Jul 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-06-02 15:15:32 +0000 (Mon, 02 Jun 2025)");

  script_name("Mageia: Security Advisory (MGASA-2025-0202)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2025-0202");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2025-0202.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=34411");
  script_xref(name:"URL", value:"https://lists.debian.org/debian-security-announce/2025/msg00117.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'catdoc' package(s) announced via the MGASA-2025-0202 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A memory corruption vulnerability exists in the Shared String Table
Record Parser implementation in the xls2csv utility version 0.95.
(CVE-2024-48877)
An integer overflow vulnerability exists in the OLE Document File
Allocation Table Parser functionality of catdoc 0.95. (CVE-2024-52035)
An integer underflow vulnerability exists in the OLE Document DIFAT
Parser functionality of catdoc 0.95. (CVE-2024-54028)");

  script_tag(name:"affected", value:"'catdoc' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"catdoc", rpm:"catdoc~0.95~5.1.mga9", rls:"MAGEIA9"))) {
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
