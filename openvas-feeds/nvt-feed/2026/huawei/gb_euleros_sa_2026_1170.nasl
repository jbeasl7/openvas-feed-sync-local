# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2026.1170");
  script_cve_id("CVE-2024-45774", "CVE-2024-45775", "CVE-2024-45776", "CVE-2024-45777", "CVE-2024-45778", "CVE-2024-45779", "CVE-2024-45780", "CVE-2024-45781", "CVE-2024-45782", "CVE-2024-45783", "CVE-2024-49504", "CVE-2024-56737", "CVE-2024-56738", "CVE-2025-0622", "CVE-2025-0624", "CVE-2025-0677", "CVE-2025-0678", "CVE-2025-0684", "CVE-2025-0685", "CVE-2025-0686", "CVE-2025-0689", "CVE-2025-0690", "CVE-2025-1118", "CVE-2025-1125");
  script_tag(name:"creation_date", value:"2026-02-02 04:58:24 +0000 (Mon, 02 Feb 2026)");
  script_version("2026-02-02T05:59:28+0000");
  script_tag(name:"last_modification", value:"2026-02-02 05:59:28 +0000 (Mon, 02 Feb 2026)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-01-08 04:15:53 +0000 (Thu, 08 Jan 2026)");

  script_name("Huawei EulerOS: Security Advisory for grub2 (EulerOS-SA-2026-1170)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT\-2\.10\.0");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2026-1170");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2026-1170");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'grub2' package(s) announced via the EulerOS-SA-2026-1170 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"GNU GRUB (aka GRUB2) through 2.12 does not use a constant-time algorithm for grub_crypto_memcmp and thus allows side-channel attacks.(CVE-2024-56738)

A flaw was found in grub2. The calculation of the translation buffer when reading a language .mo file in grub_gettext_getstr_from_position() may overflow, leading to a Out-of-bound write. This issue can be leveraged by an attacker to overwrite grub2's sensitive heap data, eventually leading to the circumvention of secure boot protections.(CVE-2024-45777)

When reading data from a hfs filesystem, grub's hfs filesystem module uses user-controlled parameters from the filesystem metadata to calculate the internal buffers size, however it misses to properly check for integer overflows. A maliciouly crafted filesystem may lead some of those buffer size calculation to overflow, causing it to perform a grub_malloc() operation with a smaller size than expected. As a result the hfsplus_open_compressed_real() function will write past of the internal buffer length. This flaw may be leveraged to corrupt grub's internal critical data and may result in arbitrary code execution by-passing secure boot protections.(CVE-2025-1125)

A flaw was found in grub2. Grub's dump command is not blocked when grub is in lockdown mode, which allows the user to read any memory information, and an attacker may leverage this in order to extract signatures, salts, and other sensitive information from the memory.(CVE-2025-1118)

A flaw was found in grub2. During the network boot process, when trying to search for the configuration file, grub copies data from a user controlled environment variable into an internal buffer using the grub_strcpy() function. During this step, it fails to consider the environment variable length when allocating the internal buffer, resulting in an out-of-bounds write. If correctly exploited, this issue may result in remote code execution through the same network segment grub is searching for the boot information, which can be used to by-pass secure boot protections.(CVE-2025-0624)

The read command is used to read the keyboard input from the user, while reads it keeps the input length in a 32-bit integer value which is further used to reallocate the line buffer to accept the next character. During this process, with a line big enough it's possible to make this variable to overflow leading to a out-of-bounds write in the heap based buffer. This flaw may be leveraged to corrupt grub's internal critical data and secure boot bypass is not discarded as consequence.(CVE-2025-0690)
When reading data from disk, the grub's UDF filesystem module utilizes the user controlled data length metadata to allocate its internal buffers. In certain scenarios, while iterating through disk sectors, it assumes the read size from the disk is always smaller than the allocated buffer size which is not guaranteed. A crafted filesystem image may lead to a ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'grub2' package(s) on Huawei EulerOS Virtualization release 2.10.0.");

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

if(release == "EULEROSVIRT-2.10.0") {

  if(!isnull(res = isrpmvuln(pkg:"grub2-common", rpm:"grub2-common~2.04~16.h54.eulerosv2r10", rls:"EULEROSVIRT-2.10.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-efi-x64", rpm:"grub2-efi-x64~2.04~16.h54.eulerosv2r10", rls:"EULEROSVIRT-2.10.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-efi-x64-modules", rpm:"grub2-efi-x64-modules~2.04~16.h54.eulerosv2r10", rls:"EULEROSVIRT-2.10.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-pc", rpm:"grub2-pc~2.04~16.h54.eulerosv2r10", rls:"EULEROSVIRT-2.10.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-pc-modules", rpm:"grub2-pc-modules~2.04~16.h54.eulerosv2r10", rls:"EULEROSVIRT-2.10.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-tools", rpm:"grub2-tools~2.04~16.h54.eulerosv2r10", rls:"EULEROSVIRT-2.10.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-tools-efi", rpm:"grub2-tools-efi~2.04~16.h54.eulerosv2r10", rls:"EULEROSVIRT-2.10.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-tools-extra", rpm:"grub2-tools-extra~2.04~16.h54.eulerosv2r10", rls:"EULEROSVIRT-2.10.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-tools-minimal", rpm:"grub2-tools-minimal~2.04~16.h54.eulerosv2r10", rls:"EULEROSVIRT-2.10.0"))) {
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
