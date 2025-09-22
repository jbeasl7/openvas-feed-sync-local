# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.1001005779910235102");
  script_cve_id("CVE-2023-34440", "CVE-2023-43758", "CVE-2024-24582", "CVE-2024-28047", "CVE-2024-28127", "CVE-2024-29214", "CVE-2024-31068", "CVE-2024-31157", "CVE-2024-36293", "CVE-2024-37020", "CVE-2024-39279", "CVE-2024-39355");
  script_tag(name:"creation_date", value:"2025-02-20 04:04:31 +0000 (Thu, 20 Feb 2025)");
  script_version("2025-02-20T08:47:14+0000");
  script_tag(name:"last_modification", value:"2025-02-20 08:47:14 +0000 (Thu, 20 Feb 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2025-dd577cf35f)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC40");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-dd577cf35f");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-dd577cf35f");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'microcode_ctl' package(s) announced via the FEDORA-2025-dd577cf35f advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"- Update to upstream 2.1-48. 20250211
 - Addition of 06-bf-06/0x07 microcode (in intel-ucode/06-97-02) at revision 0x38,
 - Addition of 06-bf-07/0x07 microcode (in intel-ucode/06-97-02) at revision 0x38,
 - Addition of 06-bf-06/0x07 microcode (in intel-ucode/06-97-05) at revision 0x38,
 - Addition of 06-bf-07/0x07 microcode (in intel-ucode/06-97-05) at revision 0x38,
 - Addition of 06-af-03/0x01 (SRF-SP C0) microcode at revision 0x3000330,
 - Addition of 06-b7-04/0x32 microcode (in intel-ucode/06-b7-01) at revision 0x12c,
 - Addition of 06-bf-06/0x07 microcode (in intel-ucode/06-bf-02) at revision 0x38,
 - Addition of 06-bf-07/0x07 microcode (in intel-ucode/06-bf-02) at revision 0x38,
 - Addition of 06-bf-06/0x07 microcode (in intel-ucode/06-bf-05) at revision 0x38,
 - Addition of 06-bf-07/0x07 microcode (in intel-ucode/06-bf-05) at revision 0x38,
 - Removal of 06-8f-04/0x87 (SPR-SP E0/S1) microcode (in intel-ucode/06-8f-05) at revision 0x2b000603,
 - Removal of 06-8f-04/0x10 microcode (in intel-ucode/06-8f-05) at revision 0x2c000390,
 - Removal of 06-8f-05/0x87 (SPR-SP E2) microcode at revision 0x2b000603,
 - Removal of 06-8f-05/0x10 (SPR-HBM B1) microcode at revision 0x2c000390,
 - Removal of 06-8f-06/0x87 (SPR-SP E3) microcode (in intel-ucode/06-8f-05) at revision 0x2b000603,
 - Removal of 06-8f-06/0x10 microcode (in intel-ucode/06-8f-05) at revision 0x2c000390,
 - Removal of 06-8f-07/0x87 (SPR-SP E4/S2) microcode (in intel-ucode/06-8f-05) at revision 0x2b000603,
 - Removal of 06-8f-08/0x87 (SPR-SP E5/S3) microcode (in intel-ucode/06-8f-05) at revision 0x2b000603,
 - Removal of 06-8f-08/0x10 (SPR-HBM B3) microcode (in intel-ucode/06-8f-05) at revision 0x2c000390,
 - Removal of 06-8f-04/0x87 (SPR-SP E0/S1) microcode (in intel-ucode/06-8f-06) at revision 0x2b000603,
 - Removal of 06-8f-04/0x10 microcode (in intel-ucode/06-8f-06) at revision 0x2c000390,
 - Removal of 06-8f-05/0x87 (SPR-SP E2) microcode (in intel-ucode/06-8f-06) at revision 0x2b000603,
 - Removal of 06-8f-05/0x10 (SPR-HBM B1) microcode (in intel-ucode/06-8f-06) at revision 0x2c000390,
 - Removal of 06-8f-06/0x87 (SPR-SP E3) microcode at revision 0x2b000603,
 - Removal of 06-8f-06/0x10 microcode at revision 0x2c000390,
 - Removal of 06-8f-07/0x87 (SPR-SP E4/S2) microcode (in intel-ucode/06-8f-06) at revision 0x2b000603,
 - Removal of 06-8f-08/0x87 (SPR-SP E5/S3) microcode (in intel-ucode/06-8f-06) at revision 0x2b000603,
 - Removal of 06-8f-08/0x10 (SPR-HBM B3) microcode (in intel-ucode/06-8f-06) at revision 0x2c000390,
 - Removal of 06-ba-02/0xe0 (RPL-H 6+8/P 6+8 J0) microcode (in intel-ucode/06-ba-08) at revision 0x4123,
 - Removal of 06-ba-03/0xe0 (RPL-U 2+8 Q0) microcode (in intel-ucode/06-ba-08) at revision 0x4123,
 - Removal of 06-ba-08/0xe0 microcode at revision 0x4123,
 - Update of 06-6a-06/0x87 (ICX-SP D0) microcode from revision 0xd0003e7 up to 0xd0003f5,
 - Update of 06-6c-01/0x10 (ICL-D B0) ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'microcode_ctl' package(s) on Fedora 40.");

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

  if(!isnull(res = isrpmvuln(pkg:"microcode_ctl", rpm:"microcode_ctl~2.1~61.6.fc40", rls:"FC40"))) {
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
