# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2024.599599384102977");
  script_cve_id("CVE-2024-24853", "CVE-2024-24980", "CVE-2024-25939");
  script_tag(name:"creation_date", value:"2024-09-10 12:54:26 +0000 (Tue, 10 Sep 2024)");
  script_version("2024-09-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-09-13 05:05:46 +0000 (Fri, 13 Sep 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2024-5c5c384fa7)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC40");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-5c5c384fa7");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-5c5c384fa7");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2305324");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'microcode_ctl' package(s) announced via the FEDORA-2024-5c5c384fa7 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"- Update to upstream 2.1-44. 20240813
 - Update of 06-55-07/0xbf (CLX-SP/W/X B1/L1) microcode from revision 0x5003605 up to 0x5003707,
 - Update of 06-55-0b/0xbf (CPX-SP A1) microcode from revision 0x7002802 up to 0x7002904,
 - Update of 06-6a-06/0x87 (ICX-SP D0) microcode from revision 0xd0003d1 up to 0xd0003e7,
 - Update of 06-6c-01/0x10 (ICL-D B0) microcode from revision 0x1000290 up to 0x10002b0,
 - Update of 06-7e-05/0x80 (ICL-U/Y D1) microcode from revision 0xc4 up to 0xc6,
 - Update of 06-8c-01/0x80 (TGL-UP3/UP4 B1) microcode from revision 0xb6 up to 0xb8,
 - Update of 06-8c-02/0xc2 (TGL-R C0) microcode from revision 0x36 up to 0x38,
 - Update of 06-8d-01/0xc2 (TGL-H R0) microcode from revision 0x50 up to 0x52,
 - Update of 06-8e-09/0x10 (AML-Y 2+2 H0) microcode from revision 0xf4 up to 0xf6,
 - Update of 06-8e-09/0xc0 (KBL-U/U 2+3e/Y H0/J1) microcode from revision 0xf4 up to 0xf6,
 - Update of 06-8e-0a/0xc0 (CFL-U 4+3e D0, KBL-R Y0) microcode from revision 0xf4 up to 0xf6,
 - Update of 06-8e-0b/0xd0 (WHL-U W0) microcode from revision 0xf4 up to 0xf6,
 - Update of 06-8e-0c/0x94 (AML-Y 4+2 V0, CML-U 4+2 V0, WHL-U V0) microcode from revision 0xfa up to 0xfc,
 - Update of 06-96-01/0x01 (EHL B1) microcode from revision 0x19 up to 0x1a,
 - Update of 06-9e-0a/0x22 (CFL-H/S/Xeon E U0) microcode from revision 0xf6 up to 0xf8,
 - Update of 06-9e-0b/0x02 (CFL-E/H/S B0) microcode from revision 0xf4 up to 0xf6,
 - Update of 06-9e-0c/0x22 (CFL-H/S/Xeon E P0) microcode from revision 0xf6 up to 0xf8,
 - Update of 06-9e-0d/0x22 (CFL-H/S/Xeon E R0) microcode from revision 0xfc up to 0x100,
 - Update of 06-a5-02/0x20 (CML-H R1) microcode from revision 0xfa up to 0xfc,
 - Update of 06-a5-03/0x22 (CML-S 6+2 G1) microcode from revision 0xfa up to 0xfc,
 - Update of 06-a5-05/0x22 (CML-S 10+2 Q0) microcode from revision 0xfa up to 0xfc,
 - Update of 06-a6-00/0x80 (CML-U 6+2 A0) microcode from revision 0xfa up to 0xfe,
 - Update of 06-a6-01/0x80 (CML-U 6+2 v2 K1) microcode from revision 0xfa up to 0xfc,
 - Update of 06-a7-01/0x02 (RKL-S B0) microcode from revision 0x5e up to 0x62,
 - Update of 06-aa-04/0xe6 (MTL-H/U C0) microcode from revision 0x1c up to 0x1e.
- Addresses CVE-2024-24853, CVE-2024-24980, CVE-2024-25939");

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

  if(!isnull(res = isrpmvuln(pkg:"microcode_ctl", rpm:"microcode_ctl~2.1~61.2.fc40", rls:"FC40"))) {
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
