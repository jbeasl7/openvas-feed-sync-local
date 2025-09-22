# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2025.1688");
  script_cve_id("CVE-2024-45774", "CVE-2024-45775", "CVE-2024-45776", "CVE-2024-45781", "CVE-2024-45783", "CVE-2025-0622");
  script_tag(name:"creation_date", value:"2025-06-30 11:34:40 +0000 (Mon, 30 Jun 2025)");
  script_version("2025-08-08T05:44:56+0000");
  script_tag(name:"last_modification", value:"2025-08-08 05:44:56 +0000 (Fri, 08 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:M/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-02-18 20:15:19 +0000 (Tue, 18 Feb 2025)");

  script_name("Huawei EulerOS: Security Advisory for grub2 (EulerOS-SA-2025-1688)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP13");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2025-1688");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2025-1688");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'grub2' package(s) announced via the EulerOS-SA-2025-1688 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A flaw was found in command/gpg. In some scenarios, hooks created by loaded modules are not removed when the related module is unloaded. This flaw allows an attacker to force grub2 to call the hooks once the module that registered it was unloaded, leading to a use-after-free vulnerability. If correctly exploited, this vulnerability may result in arbitrary code execution, eventually allowing the attacker to bypass secure boot protections.(CVE-2025-0622)

A flaw was found in grub2. When failing to mount an HFS+ grub, the hfsplus filesystem driver doesn't properly set an ERRNO value. This issue may lead to a NULL pointer access.(CVE-2024-45783)

A flaw was found in grub2 where the grub_extcmd_dispatcher() function calls grub_arg_list_alloc() to allocate memory for the grub's argument list. However, it fails to check in case the memory allocation fails. Once the allocation fails, a NULL point will be processed by the parse_option() function, leading grub to crash or, in some rare scenarios, corrupt the IVT data.(CVE-2024-45775)

When reading the language .mo file in grub_mofile_open(), grub2 fails to verify an integer overflow when allocating its internal buffer. A crafted .mo file may lead the buffer size calculation to overflow, leading to out-of-bound reads and writes. This flaw allows an attacker to leak sensitive data or overwrite critical data, possibly circumventing secure boot protections.(CVE-2024-45776)

A flaw was found in grub2. A specially crafted JPEG file can cause the JPEG parser of grub2 to incorrectly check the bounds of its internal buffers, resulting in an out-of-bounds write. The possibility of overwriting sensitive information to bypass secure boot protections is not discarded.(CVE-2024-45774)

A flaw was found in grub2. When reading a symbolic link's name from a UFS filesystem, grub2 fails to validate the string length taken as an input. The lack of validation may lead to a heap out-of-bounds write, causing data integrity issues and eventually allowing an attacker to circumvent secure boot protections.(CVE-2024-45781)");

  script_tag(name:"affected", value:"'grub2' package(s) on Huawei EulerOS V2.0SP13.");

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

if(release == "EULEROS-2.0SP13") {

  if(!isnull(res = isrpmvuln(pkg:"grub2-common", rpm:"grub2-common~2.06~44.h10.eulerosv2r13", rls:"EULEROS-2.0SP13"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-efi-x64", rpm:"grub2-efi-x64~2.06~44.h10.eulerosv2r13", rls:"EULEROS-2.0SP13"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-efi-x64-modules", rpm:"grub2-efi-x64-modules~2.06~44.h10.eulerosv2r13", rls:"EULEROS-2.0SP13"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-pc", rpm:"grub2-pc~2.06~44.h10.eulerosv2r13", rls:"EULEROS-2.0SP13"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-pc-modules", rpm:"grub2-pc-modules~2.06~44.h10.eulerosv2r13", rls:"EULEROS-2.0SP13"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-tools", rpm:"grub2-tools~2.06~44.h10.eulerosv2r13", rls:"EULEROS-2.0SP13"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-tools-efi", rpm:"grub2-tools-efi~2.06~44.h10.eulerosv2r13", rls:"EULEROS-2.0SP13"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-tools-extra", rpm:"grub2-tools-extra~2.06~44.h10.eulerosv2r13", rls:"EULEROS-2.0SP13"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-tools-minimal", rpm:"grub2-tools-minimal~2.06~44.h10.eulerosv2r13", rls:"EULEROS-2.0SP13"))) {
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
