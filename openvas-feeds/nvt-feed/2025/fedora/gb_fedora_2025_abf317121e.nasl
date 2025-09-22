# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.9798102317121101");
  script_cve_id("CVE-2024-28956", "CVE-2024-43420", "CVE-2024-45332", "CVE-2025-20012", "CVE-2025-20054", "CVE-2025-20103", "CVE-2025-20623", "CVE-2025-24495");
  script_tag(name:"creation_date", value:"2025-05-28 04:06:45 +0000 (Wed, 28 May 2025)");
  script_version("2025-05-28T05:40:15+0000");
  script_tag(name:"last_modification", value:"2025-05-28 05:40:15 +0000 (Wed, 28 May 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2025-abf317121e)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC42");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-abf317121e");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-abf317121e");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'microcode_ctl' package(s) announced via the FEDORA-2025-abf317121e advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"- Update to upstream 2.1-49. 20250512
 - Addition of 06-ad-01/0x20 (GNR-AP/SP H0) microcode at revision
 0xa0000d1,
 - Addition of 06-ad-01/0x95 (GNR-AP/SP B0) microcode at revision
 0x10003a2,
 - Addition of 06-b5-00/0x80 (ARL-U A1) microcode at revision 0xa,
 - Addition of 06-bd-01/0x80 (LNL B0) microcode at revision 0x11f,
 - Addition of 06-c5-02/0x82 (ARL-H A1) microcode at revision 0x118,
 - Addition of 06-c6-02/0x82 (ARL-HX 8P/S B0) microcode (in
 intel-ucode/06-c5-02) at revision 0x118,
 - Addition of 06-c6-04/0x82 microcode (in intel-ucode/06-c5-02) at
 revision 0x118,
 - Addition of 06-ca-02/0x82 microcode (in intel-ucode/06-c5-02) at
 revision 0x118,
 - Addition of 06-c5-02/0x82 (ARL-H A1) microcode (in
 intel-ucode/06-c6-02) at revision 0x118,
 - Addition of 06-c6-02/0x82 (ARL-HX 8P/S B0) microcode at revision
 0x118,
 - Addition of 06-c6-04/0x82 microcode (in intel-ucode/06-c6-02) at
 revision 0x118,
 - Addition of 06-ca-02/0x82 microcode (in intel-ucode/06-c6-02) at
 revision 0x118,
 - Removal of 06-55-06/0xbf (CLX-SP B0) microcode at revision 0x4003605,
 - Removal of 06-cf-01/0x87 (EMR-SP A0) microcode at revision 0x21000291,
 - Removal of 06-cf-02/0x87 (EMR-SP A1) microcode (in
 intel-ucode/06-cf-01) at revision 0x21000291,
 - Update of 06-55-07/0xbf (CLX-SP/W/X B1/L1) microcode from revision
 0x5003707 up to 0x5003901,
 - Update of 06-55-0b/0xbf (CPX-SP A1) microcode from revision 0x7002904
 up to 0x7002b01,
 - Update of 06-6a-06/0x87 (ICX-SP D0) microcode from revision 0xd0003f5
 up to 0xd000404,
 - Update of 06-6c-01/0x10 (ICL-D B0) microcode from revision 0x10002c0
 up to 0x10002d0,
 - Update of 06-7a-08/0x01 (GLK-R R0) microcode from revision 0x24 up
 to 0x26,
 - Update of 06-7e-05/0x80 (ICL-U/Y D1) microcode from revision 0xc6
 up to 0xca,
 - Update of 06-8c-01/0x80 (TGL-UP3/UP4 B1) microcode from revision
 0xb8 up to 0xbc,
 - Update of 06-8c-02/0xc2 (TGL-R C0) microcode from revision 0x38 up
 to 0x3c,
 - Update of 06-8d-01/0xc2 (TGL-H R0) microcode from revision 0x52 up
 to 0x56,
 - Update of 06-8e-0c/0x94 (AML-Y 4+2 V0, CML-U 4+2 V0, WHL-U V0)
 microcode from revision 0xfc up to 0x100,
 - Update of 06-8f-04/0x87 (SPR-SP E0/S1) microcode (in
 intel-ucode/06-8f-07) from revision 0x2b000620 up to 0x2b000639,
 - Update of 06-8f-05/0x87 (SPR-SP E2) microcode (in
 intel-ucode/06-8f-07) from revision 0x2b000620 up to 0x2b000639,
 - Update of 06-8f-06/0x87 (SPR-SP E3) microcode (in
 intel-ucode/06-8f-07) from revision 0x2b000620 up to 0x2b000639,
 - Update of 06-8f-07/0x87 (SPR-SP E4/S2) microcode from revision
 0x2b000620 up to 0x2b000639,
 - Update of 06-8f-08/0x87 (SPR-SP E5/S3) microcode (in
 intel-ucode/06-8f-07) from revision 0x2b000620 up to 0x2b000639,
 - Update of 06-8f-04/0x10 microcode (in intel-ucode/06-8f-08) from
 revision 0x2c0003e0 up to 0x2c0003f7,
 - Update of 06-8f-04/0x87 (SPR-SP E0/S1) microcode (in
 intel-ucode/06-8f-08) from revision ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'microcode_ctl' package(s) on Fedora 42.");

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

  if(!isnull(res = isrpmvuln(pkg:"microcode_ctl", rpm:"microcode_ctl~2.1~70.fc42", rls:"FC42"))) {
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
