# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2026.1424");
  script_cve_id("CVE-2021-32256", "CVE-2022-48064", "CVE-2025-11082", "CVE-2025-11083", "CVE-2025-11412", "CVE-2025-11494", "CVE-2025-11840");
  script_tag(name:"creation_date", value:"2026-03-16 13:39:49 +0000 (Mon, 16 Mar 2026)");
  script_version("2026-03-17T05:57:27+0000");
  script_tag(name:"last_modification", value:"2026-03-17 05:57:27 +0000 (Tue, 17 Mar 2026)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-10-03 16:52:47 +0000 (Fri, 03 Oct 2025)");

  script_name("Huawei EulerOS: Security Advisory for gdb (EulerOS-SA-2026-1424)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT\-2\.12\.1");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2026-1424");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2026-1424");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'gdb' package(s) announced via the EulerOS-SA-2026-1424 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An issue was discovered in GNU libiberty, as distributed in GNU Binutils 2.36. It is a stack-overflow issue in demangle_type in rust-demangle.c.(CVE-2021-32256)

A flaw has been found in GNU Binutils 2.45. Impacted is the function _bfd_elf_parse_eh_frame of the file bfd/elf-eh-frame.c of the component Linker. Executing manipulation can lead to heap-based buffer overflow. The attack is restricted to local execution. The exploit has been published and may be used. This patch is called ea1a0737c7692737a644af0486b71e4a392cbca8. A patch should be applied to remediate this issue. The code maintainer replied with '[f]ixed for 2.46'.(CVE-2025-11082)

A vulnerability has been found in GNU Binutils 2.45. This impacts the function bfd_elf_gc_record_vtentry of the file bfd/elflink.c of the component Linker. The manipulation leads to out-of-bounds read. Local access is required to approach this attack. The exploit has been disclosed to the public and may be used. The identifier of the patch is 047435dd988a3975d40c6626a8f739a0b2e154bc. To fix this issue, it is recommended to deploy a patch.(CVE-2025-11412)

A vulnerability was found in GNU Binutils 2.45. Impacted is the function _bfd_x86_elf_late_size_sections of the file bfd/elfxx-x86.c of the component Linker. The manipulation results in out-of-bounds read. The attack needs to be approached locally. The exploit has been made public and could be used. The patch is identified as b6ac5a8a5b82f0ae6a4642c8d7149b325f4cc60a. A patch should be applied to remediate this issue.(CVE-2025-11494)

A weakness has been identified in GNU Binutils 2.45. The affected element is the function vfinfo of the file ldmisc.c. Executing manipulation can lead to out-of-bounds read. The attack can only be executed locally. The exploit has been made available to the public and could be exploited. This patch is called 16357. It is best practice to apply a patch to resolve this issue.(CVE-2025-11840)

A vulnerability has been found in GNU Binutils 2.45. The affected element is the function elf_swap_shdr in the library bfd/elfcode.h of the component Linker. The manipulation leads to heap-based buffer overflow. The attack must be carried out locally. The exploit has been disclosed to the public and may be used. The identifier of the patch is 9ca499644a21ceb3f946d1c179c38a83be084490. To fix this issue, it is recommended to deploy a patch. The code maintainer replied with '[f]ixed for 2.46'.(CVE-2025-11083)

GNU Binutils before 2.40 was discovered to contain an excessive memory consumption vulnerability via the function bfd_dwarf2_find_nearest_line_with_alt at dwarf2.c. The attacker could supply a crafted ELF file and cause a DNS attack.(CVE-2022-48064)");

  script_tag(name:"affected", value:"'gdb' package(s) on Huawei EulerOS Virtualization release 2.12.1.");

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

if(release == "EULEROSVIRT-2.12.1") {

  if(!isnull(res = isrpmvuln(pkg:"gdb", rpm:"gdb~11.1~3.h9.eulerosv2r12", rls:"EULEROSVIRT-2.12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gdb-headless", rpm:"gdb-headless~11.1~3.h9.eulerosv2r12", rls:"EULEROSVIRT-2.12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gdb-help", rpm:"gdb-help~11.1~3.h9.eulerosv2r12", rls:"EULEROSVIRT-2.12.1"))) {
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
