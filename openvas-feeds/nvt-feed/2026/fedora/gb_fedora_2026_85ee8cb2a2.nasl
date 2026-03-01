# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2026.85101101899982972");
  script_tag(name:"creation_date", value:"2026-02-20 04:37:04 +0000 (Fri, 20 Feb 2026)");
  script_version("2026-02-20T05:55:45+0000");
  script_tag(name:"last_modification", value:"2026-02-20 05:55:45 +0000 (Fri, 20 Feb 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2026-85ee8cb2a2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC42");

  script_xref(name:"Advisory-ID", value:"FEDORA-2026-85ee8cb2a2");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2026-85ee8cb2a2");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2431378");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'microcode_ctl' package(s) announced via the FEDORA-2026-85ee8cb2a2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"- Update to upstream 2.1-51. 20260210
 - Addition of 06-ae-01/0x97 (GNR-D B0/B1) microcode at revision
 0x10002f3,
 - Update of 06-6a-06/0x87 (ICX-SP D0) microcode from revision 0xd000410
 up to 0xd000421,
 - Update of 06-6c-01/0x10 (ICL-D B0) microcode from revision 0x10002e0
 up to 0x10002f1,
 - Update of 06-7e-05/0x80 (ICL-U/Y D1) microcode from revision 0xca
 up to 0xcc,
 - Update of 06-8c-01/0x80 (TGL-UP3/UP4 B1) microcode from revision
 0xbc up to 0xbe,
 - Update of 06-8c-02/0xc2 (TGL-R C0) microcode from revision 0x3c up
 to 0x3e,
 - Update of 06-8d-01/0xc2 (TGL-H R0) microcode from revision 0x56 up
 to 0x58,
 - Update of 06-8f-04/0x87 (SPR-SP E0/S1) microcode (in
 intel-ucode/06-8f-07) from revision 0x2b000643 up to 0x2b000661,
 - Update of 06-8f-05/0x87 (SPR-SP E2) microcode (in
 intel-ucode/06-8f-07) from revision 0x2b000643 up to 0x2b000661,
 - Update of 06-8f-06/0x87 (SPR-SP E3) microcode (in
 intel-ucode/06-8f-07) from revision 0x2b000643 up to 0x2b000661,
 - Update of 06-8f-07/0x87 (SPR-SP E4/S2) microcode from revision
 0x2b000643 up to 0x2b000661,
 - Update of 06-8f-08/0x87 (SPR-SP E5/S3) microcode (in
 intel-ucode/06-8f-07) from revision 0x2b000643 up to 0x2b000661,
 - Update of 06-8f-04/0x10 microcode (in intel-ucode/06-8f-08) from
 revision 0x2c000401 up to 0x2c000421,
 - Update of 06-8f-04/0x87 (SPR-SP E0/S1) microcode (in
 intel-ucode/06-8f-08) from revision 0x2b000643 up to 0x2b000661,
 - Update of 06-8f-05/0x10 (SPR-HBM B1) microcode (in
 intel-ucode/06-8f-08) from revision 0x2c000401 up to 0x2c000421,
 - Update of 06-8f-05/0x87 (SPR-SP E2) microcode (in
 intel-ucode/06-8f-08) from revision 0x2b000643 up to 0x2b000661,
 - Update of 06-8f-06/0x10 microcode (in intel-ucode/06-8f-08) from
 revision 0x2c000401 up to 0x2c000421,
 - Update of 06-8f-06/0x87 (SPR-SP E3) microcode (in
 intel-ucode/06-8f-08) from revision 0x2b000643 up to 0x2b000661,
 - Update of 06-8f-07/0x87 (SPR-SP E4/S2) microcode (in
 intel-ucode/06-8f-08) from revision 0x2b000643 up to 0x2b000661,
 - Update of 06-8f-08/0x10 (SPR-HBM B3) microcode from revision
 0x2c000401 up to 0x2c000421,
 - Update of 06-8f-08/0x87 (SPR-SP E5/S3) microcode from revision
 0x2b000643 up to 0x2b000661,
 - Update of 06-97-02/0x07 (ADL-HX/S 8+8 C0) microcode from revision
 0x3a up to 0x3e,
 - Update of 06-97-05/0x07 (ADL-S 6+0 K0) microcode (in
 intel-ucode/06-97-02) from revision 0x3a up to 0x3e,
 - Update of 06-bf-02/0x07 (ADL C0) microcode (in intel-ucode/06-97-02)
 from revision 0x3a up to 0x3e,
 - Update of 06-bf-05/0x07 (ADL C0) microcode (in intel-ucode/06-97-02)
 from revision 0x3a up to 0x3e,
 - Update of 06-bf-06/0x07 microcode (in intel-ucode/06-97-02) from
 revision 0x3a up to 0x3e,
 - Update of 06-bf-07/0x07 microcode (in intel-ucode/06-97-02) from
 revision 0x3a up to 0x3e,
 - Update of 06-97-02/0x07 (ADL-HX/S 8+8 C0) microcode (in
 intel-ucode/06-97-05) from revision 0x3a up to 0x3e,
 - ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"microcode_ctl", rpm:"microcode_ctl~2.1~70.1.fc42", rls:"FC42"))) {
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
