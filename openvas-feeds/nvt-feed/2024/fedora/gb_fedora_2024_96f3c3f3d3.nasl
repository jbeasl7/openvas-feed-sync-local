# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.887363");
  script_cve_id("CVE-2023-22655", "CVE-2023-23583", "CVE-2023-28746", "CVE-2023-38575", "CVE-2023-39368", "CVE-2023-42667", "CVE-2023-43490", "CVE-2023-45733", "CVE-2023-46103", "CVE-2023-49141");
  script_tag(name:"creation_date", value:"2024-08-08 04:04:32 +0000 (Thu, 08 Aug 2024)");
  script_version("2024-09-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-09-13 05:05:46 +0000 (Fri, 13 Sep 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-28 17:07:45 +0000 (Tue, 28 Nov 2023)");

  script_name("Fedora: Security Advisory (FEDORA-2024-96f3c3f3d3)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC40");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-96f3c3f3d3");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-96f3c3f3d3");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2270698");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2270700");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2270701");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2270703");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2270704");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2270720");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2270731");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2270735");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2270736");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2270737");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2292296");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2292297");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2292300");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2292301");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2295853");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'microcode_ctl' package(s) announced via the FEDORA-2024-96f3c3f3d3 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"- Update to upstream 2.1-43. 20240531
- Addition of 06-aa-04/0xe6 (MTL-H/U C0) microcode at revision 0x1c,
- Addition of 06-ba-08/0xe0 microcode (in intel-ucode/06-ba-02) at revision 0x4121,
- Addition of 06-ba-08/0xe0 microcode (in intel-ucode/06-ba-03) at revision 0x4121,
- Addition of 06-ba-08/0xe0 microcode at revision 0x4121,
- Addition of 06-cf-01/0x87 (EMR-SP A0) microcode at revision 0x21000230,
- Addition of 06-cf-02/0x87 (EMR-SP A1) microcode (in intel-ucode/06-cf-01) at revision 0x21000230,
- Addition of 06-cf-01/0x87 (EMR-SP A0) microcode (in intel-ucode/06-cf-02) at revision 0x21000230,
- Addition of 06-cf-02/0x87 (EMR-SP A1) microcode at revision 0x21000230,
- Removal of 06-8f-04/0x10 microcode at revision 0x2c000290,
- Removal of 06-8f-04/0x87 (SPR-SP E0/S1) microcode at revision 0x2b0004d0,
- Removal of 06-8f-05/0x10 (SPR-HBM B1) microcode (in intel-ucode/06-8f-04) at revision 0x2c000290,
- Removal of 06-8f-05/0x87 (SPR-SP E2) microcode (in intel-ucode/06-8f-04) at revision 0x2b0004d0,
- Removal of 06-8f-06/0x10 microcode (in intel-ucode/06-8f-04) at revision 0x2c000290,
- Removal of 06-8f-06/0x87 (SPR-SP E3) microcode (in intel-ucode/06-8f-04) at revision 0x2b0004d0,
- Update of 06-55-03/0x97 (SKX-SP B1) microcode from revision 0x1000181 up to 0x1000191,
- Update of 06-55-06/0xbf (CLX-SP B0) microcode from revision 0x4003604 up to 0x4003605,
- Update of 06-55-07/0xbf (CLX-SP/W/X B1/L1) microcode from revision 0x5003604 up to 0x5003605,
- Update of 06-55-0b/0xbf (CPX-SP A1) microcode from revision 0x7002703 up to 0x7002802,
- Update of 06-56-05/0x10 (BDX-NS A0/A1, HWL A1) microcode from revision 0xe000014 up to 0xe000015,
- Update of 06-5f-01/0x01 (DNV B0) microcode from revision 0x38 up to 0x3e,
- Update of 06-6a-06/0x87 (ICX-SP D0) microcode from revision 0xd0003b9 up to 0xd0003d1,
- Update of 06-6c-01/0x10 (ICL-D B0) microcode from revision 0x1000268 up to 0x1000290,
- Update of 06-7a-01/0x01 (GLK B0) microcode from revision 0x3e up to 0x42,
- Update of 06-7a-08/0x01 (GLK-R R0) microcode from revision 0x22 up to 0x24,
- Update of 06-7e-05/0x80 (ICL-U/Y D1) microcode from revision 0xc2 up to 0xc4,
- Update of 06-8c-01/0x80 (TGL-UP3/UP4 B1) microcode from revision 0xb4 up to 0xb6,
- Update of 06-8c-02/0xc2 (TGL-R C0) microcode from revision 0x34 up to 0x36,
- Update of 06-8d-01/0xc2 (TGL-H R0) microcode from revision 0x4e up to 0x50,
- Update of 06-8e-0c/0x94 (AML-Y 4+2 V0, CML-U 4+2 V0, WHL-U V0) microcode from revision 0xf8 up to 0xfa,
- Update of 06-8f-04/0x10 microcode (in intel-ucode/06-8f-05) from revision 0x2c000290 up to 0x2c000390,
- Update of 06-8f-04/0x87 (SPR-SP E0/S1) microcode (in intel-ucode/06-8f-05) from revision 0x2b0004d0 up to 0x2b0005c0,
- Update of 06-8f-05/0x10 (SPR-HBM B1) microcode from revision 0x2c000290 up to 0x2c000390,
- Update of 06-8f-05/0x87 (SPR-SP E2) microcode from revision 0x2b0004d0 up to 0x2b0005c0,
- Update of ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"microcode_ctl", rpm:"microcode_ctl~2.1~61.1.fc40", rls:"FC40"))) {
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
