# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2025.1634");
  script_cve_id("CVE-2024-45777", "CVE-2024-45778", "CVE-2024-45779", "CVE-2024-45780", "CVE-2024-45782", "CVE-2025-0624", "CVE-2025-0677", "CVE-2025-0678", "CVE-2025-0684", "CVE-2025-0685", "CVE-2025-0686", "CVE-2025-0689", "CVE-2025-0690", "CVE-2025-1118", "CVE-2025-1125");
  script_tag(name:"creation_date", value:"2025-06-11 04:32:50 +0000 (Wed, 11 Jun 2025)");
  script_version("2025-08-14T05:40:53+0000");
  script_tag(name:"last_modification", value:"2025-08-14 05:40:53 +0000 (Thu, 14 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-03-07 20:42:19 +0000 (Fri, 07 Mar 2025)");

  script_name("Huawei EulerOS: Security Advisory for grub2 (EulerOS-SA-2025-1634)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP13\-X86_64");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2025-1634");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2025-1634");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'grub2' package(s) announced via the EulerOS-SA-2025-1634 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A flaw was found in grub2. When reading data from a squash4 filesystem, grub's squash4 fs module uses user-controlled parameters from the filesystem geometry to determine the internal buffer size, however, it improperly checks for integer overflows. A maliciously crafted filesystem may lead some of those buffer size calculations to overflow, causing it to perform a grub_malloc() operation with a smaller size than expected. As a result, the direct_read() will perform a heap based out-of-bounds write during data reading. This flaw may be leveraged to corrupt grub's internal critical data and may result in arbitrary code execution, by-passing secure boot protections.(CVE-2025-0678)

A flaw was found in grub2. When reading tar files, grub2 allocates an internal buffer for the file name. However, it fails to properly verify the allocation against possible integer overflows. It's possible to cause the allocation length to overflow with a crafted tar file, leading to a heap out-of-bounds write. This flaw eventually allows an attacker to circumvent secure boot protections.(CVE-2024-45780)

A stack overflow flaw was found when reading a BFS file system. A crafted BFS filesystem may lead to an uncontrolled loop, causing grub2 to crash.(CVE-2024-45778)

A flaw was found in grub2. When performing a symlink lookup from a romfs filesystem, grub's romfs filesystem module uses user-controlled parameters from the filesystem geometry to determine the internal buffer size, however, it improperly checks for integer overflows. A maliciously crafted filesystem may lead some of those buffer size calculations to overflow, causing it to perform a grub_malloc() operation with a smaller size than expected. As a result, the grub_romfs_read_symlink() may cause out-of-bounds writes when the calling grub_disk_read() function. This issue may be leveraged to corrupt grub's internal critical data and can result in arbitrary code execution by-passing secure boot protections.(CVE-2025-0686)

A flaw was found in the HFS filesystem. When reading an HFS volume's name at grub_fs_mount(), the HFS filesystem driver performs a strcpy() using the user-provided volume name as input without properly validating the volume name's length. This issue may read to a heap-based out-of-bounds writer, impacting grub's sensitive data integrity and eventually leading to a secure boot protection bypass.(CVE-2024-45782)

A flaw was found in grub2. When reading data from a jfs filesystem, grub's jfs filesystem module uses user-controlled parameters from the filesystem geometry to determine the internal buffer size, however, it improperly checks for integer overflows. A maliciouly crafted filesystem may lead some of those buffer size calculations to overflow, causing it to perform a grub_malloc() operation with a smaller size than expected. As a result, the grub_jfs_lookup_symlink() function will write past the internal buffer ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'grub2' package(s) on Huawei EulerOS V2.0SP13(x86_64).");

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

if(release == "EULEROS-2.0SP13-x86_64") {

  if(!isnull(res = isrpmvuln(pkg:"grub2-common", rpm:"grub2-common~2.06~44.h9.eulerosv2r13", rls:"EULEROS-2.0SP13-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-efi-x64", rpm:"grub2-efi-x64~2.06~44.h9.eulerosv2r13", rls:"EULEROS-2.0SP13-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-efi-x64-modules", rpm:"grub2-efi-x64-modules~2.06~44.h9.eulerosv2r13", rls:"EULEROS-2.0SP13-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-pc", rpm:"grub2-pc~2.06~44.h9.eulerosv2r13", rls:"EULEROS-2.0SP13-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-pc-modules", rpm:"grub2-pc-modules~2.06~44.h9.eulerosv2r13", rls:"EULEROS-2.0SP13-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-tools", rpm:"grub2-tools~2.06~44.h9.eulerosv2r13", rls:"EULEROS-2.0SP13-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-tools-efi", rpm:"grub2-tools-efi~2.06~44.h9.eulerosv2r13", rls:"EULEROS-2.0SP13-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-tools-extra", rpm:"grub2-tools-extra~2.06~44.h9.eulerosv2r13", rls:"EULEROS-2.0SP13-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-tools-minimal", rpm:"grub2-tools-minimal~2.06~44.h9.eulerosv2r13", rls:"EULEROS-2.0SP13-x86_64"))) {
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
