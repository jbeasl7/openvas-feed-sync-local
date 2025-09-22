# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2025.1587");
  script_cve_id("CVE-2024-45774", "CVE-2024-45775", "CVE-2024-45776", "CVE-2024-45777", "CVE-2024-45778", "CVE-2024-45779", "CVE-2024-45780", "CVE-2024-45781", "CVE-2024-45782", "CVE-2024-45783", "CVE-2024-49504", "CVE-2025-0622", "CVE-2025-0624", "CVE-2025-0677", "CVE-2025-0678", "CVE-2025-0684", "CVE-2025-0685", "CVE-2025-0686", "CVE-2025-0689", "CVE-2025-0690", "CVE-2025-1118", "CVE-2025-1125");
  script_tag(name:"creation_date", value:"2025-06-11 04:32:50 +0000 (Wed, 11 Jun 2025)");
  script_version("2025-08-14T05:40:53+0000");
  script_tag(name:"last_modification", value:"2025-08-14 05:40:53 +0000 (Thu, 14 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-03-07 20:42:19 +0000 (Fri, 07 Mar 2025)");

  script_name("Huawei EulerOS: Security Advisory for grub2 (EulerOS-SA-2025-1587)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP12\-X86_64");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2025-1587");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2025-1587");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'grub2' package(s) announced via the EulerOS-SA-2025-1587 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A stack overflow flaw was found when reading a BFS file system. A crafted BFS filesystem may lead to an uncontrolled loop, causing grub2 to crash.(CVE-2024-45778)

When reading data from a hfs filesystem, grub's hfs filesystem module uses user-controlled parameters from the filesystem metadata to calculate the internal buffers size, however it misses to properly check for integer overflows. A maliciouly crafted filesystem may lead some of those buffer size calculation to overflow, causing it to perform a grub_malloc() operation with a smaller size than expected. As a result the hfsplus_open_compressed_real() function will write past of the internal buffer length. This flaw may be leveraged to corrupt grub's internal critical data and may result in arbitrary code execution by-passing secure boot protections.(CVE-2025-1125)

When reading data from disk, the grub's UDF filesystem module utilizes the user controlled data length metadata to allocate its internal buffers. In certain scenarios, while iterating through disk sectors, it assumes the read size from the disk is always smaller than the allocated buffer size which is not guaranteed. A crafted filesystem image may lead to a heap-based buffer overflow resulting in critical data to be corrupted, resulting in the risk of arbitrary code execution by-passing secure boot protections.(CVE-2025-0689)

A flaw was found in grub2. When reading data from a jfs filesystem, grub's jfs filesystem module uses user-controlled parameters from the filesystem geometry to determine the internal buffer size, however, it improperly checks for integer overflows. A maliciouly crafted filesystem may lead some of those buffer size calculations to overflow, causing it to perform a grub_malloc() operation with a smaller size than expected. As a result, the grub_jfs_lookup_symlink() function will write past the internal buffer length during grub_jfs_read_file(). This issue can be leveraged to corrupt grub's internal critical data and may result in arbitrary code execution, by-passing secure boot protections.(CVE-2025-0685)

A flaw was found in grub2. When performing a symlink lookup, the grub's UFS module checks the inode's data size to allocate the internal buffer to read the file content, however, it fails to check if the symlink data size has overflown. When this occurs, grub_malloc() may be called with a smaller value than needed. When further reading the data from the disk into the buffer, the grub_ufs_lookup_symlink() function will write past the end of the allocated size. An attack can leverage this by crafting a malicious filesystem, and as a result, it will corrupt data stored in the heap, allowing for arbitrary code execution used to by-pass secure boot mechanisms.(CVE-2025-0677)

A flaw was found in grub2. During the network boot process, when trying to search for the configuration file, grub copies data from a user controlled ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'grub2' package(s) on Huawei EulerOS V2.0SP12(x86_64).");

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

if(release == "EULEROS-2.0SP12-x86_64") {

  if(!isnull(res = isrpmvuln(pkg:"grub2-common", rpm:"grub2-common~2.06~20.h21.eulerosv2r12", rls:"EULEROS-2.0SP12-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-efi-x64", rpm:"grub2-efi-x64~2.06~20.h21.eulerosv2r12", rls:"EULEROS-2.0SP12-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-efi-x64-modules", rpm:"grub2-efi-x64-modules~2.06~20.h21.eulerosv2r12", rls:"EULEROS-2.0SP12-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-pc", rpm:"grub2-pc~2.06~20.h21.eulerosv2r12", rls:"EULEROS-2.0SP12-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-pc-modules", rpm:"grub2-pc-modules~2.06~20.h21.eulerosv2r12", rls:"EULEROS-2.0SP12-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-tools", rpm:"grub2-tools~2.06~20.h21.eulerosv2r12", rls:"EULEROS-2.0SP12-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-tools-efi", rpm:"grub2-tools-efi~2.06~20.h21.eulerosv2r12", rls:"EULEROS-2.0SP12-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-tools-extra", rpm:"grub2-tools-extra~2.06~20.h21.eulerosv2r12", rls:"EULEROS-2.0SP12-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-tools-minimal", rpm:"grub2-tools-minimal~2.06~20.h21.eulerosv2r12", rls:"EULEROS-2.0SP12-x86_64"))) {
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
