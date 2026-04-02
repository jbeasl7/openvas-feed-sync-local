# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2026.1364");
  script_cve_id("CVE-2025-54771", "CVE-2025-61661", "CVE-2025-61662", "CVE-2025-61663", "CVE-2025-61664");
  script_tag(name:"creation_date", value:"2026-03-16 05:12:13 +0000 (Mon, 16 Mar 2026)");
  script_version("2026-03-16T06:13:25+0000");
  script_tag(name:"last_modification", value:"2026-03-16 06:13:25 +0000 (Mon, 16 Mar 2026)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-01-08 16:55:54 +0000 (Thu, 08 Jan 2026)");

  script_name("Huawei EulerOS: Security Advisory for grub2 (EulerOS-SA-2026-1364)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP12\-X86_64");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2026-1364");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2026-1364");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'grub2' package(s) announced via the EulerOS-SA-2026-1364 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A Use-After-Free vulnerability has been discovered in GRUB's gettext module. This flaw stems from a programming error where the gettext command remains registered in memory after its module is unloaded. An attacker can exploit this condition by invoking the orphaned command, causing the application to access a memory location that is no longer valid. An attacker could exploit this vulnerability to cause grub to crash, leading to a Denial of Service. Possible data integrity or confidentiality compromise is not discarded.(CVE-2025-61662)

A vulnerability in the GRUB2 bootloader has been identified in the normal module. This flaw, a memory Use After Free issue, occurs because the normal_exit command is not properly unregistered when its related module is unloaded. An attacker can exploit this condition by invoking the command after the module has been removed, causing the system to improperly access a previously freed memory location. This leads to a system crash or possible impacts in data confidentiality and integrity.(CVE-2025-61664)

A use-after-free vulnerability has been identified in the GNU GRUB (Grand Unified Bootloader). The flaw occurs because the file-closing process incorrectly retains a memory pointer, leaving an invalid reference to a file system structure. An attacker could exploit this vulnerability to cause grub to crash, leading to a Denial of Service. Possible data integrity or confidentiality compromise is not discarded.(CVE-2025-54771)

A vulnerability has been identified in the GRUB2 bootloader's normal command that poses an immediate Denial of Service (DoS) risk. This flaw is a Use-after-Free issue, caused because the normal command is not properly unregistered when the module is unloaded. An attacker who can execute this command can force the system to access memory locations that are no longer valid. Successful exploitation leads directly to system instability, which can result in a complete crash and halt system availability. Impact on the data integrity and confidentiality is also not discarded.(CVE-2025-61663)

A vulnerability has been identified in the GRUB (Grand Unified Bootloader) component. This flaw occurs because the bootloader mishandles string conversion when reading information from a USB device, allowing an attacker to exploit inconsistent length values. A local attacker can connect a maliciously configured USB device during the boot sequence to trigger this issue. A successful exploitation may lead GRUB to crash, leading to a Denial of Service. Data corruption may be also possible, although given the complexity of the exploit the impact is most likely limited.(CVE-2025-61661)");

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

  if(!isnull(res = isrpmvuln(pkg:"grub2-common", rpm:"grub2-common~2.06~20.h23.eulerosv2r12", rls:"EULEROS-2.0SP12-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-efi-x64", rpm:"grub2-efi-x64~2.06~20.h23.eulerosv2r12", rls:"EULEROS-2.0SP12-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-efi-x64-modules", rpm:"grub2-efi-x64-modules~2.06~20.h23.eulerosv2r12", rls:"EULEROS-2.0SP12-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-pc", rpm:"grub2-pc~2.06~20.h23.eulerosv2r12", rls:"EULEROS-2.0SP12-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-pc-modules", rpm:"grub2-pc-modules~2.06~20.h23.eulerosv2r12", rls:"EULEROS-2.0SP12-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-tools", rpm:"grub2-tools~2.06~20.h23.eulerosv2r12", rls:"EULEROS-2.0SP12-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-tools-efi", rpm:"grub2-tools-efi~2.06~20.h23.eulerosv2r12", rls:"EULEROS-2.0SP12-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-tools-extra", rpm:"grub2-tools-extra~2.06~20.h23.eulerosv2r12", rls:"EULEROS-2.0SP12-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-tools-minimal", rpm:"grub2-tools-minimal~2.06~20.h23.eulerosv2r12", rls:"EULEROS-2.0SP12-x86_64"))) {
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
