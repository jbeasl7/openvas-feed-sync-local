# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2016.2100.1");
  script_cve_id("CVE-2014-3672", "CVE-2016-3158", "CVE-2016-3159", "CVE-2016-3710", "CVE-2016-3960", "CVE-2016-4001", "CVE-2016-4002", "CVE-2016-4020", "CVE-2016-4037", "CVE-2016-4439", "CVE-2016-4441", "CVE-2016-4453", "CVE-2016-4454", "CVE-2016-4952", "CVE-2016-4962", "CVE-2016-4963", "CVE-2016-5105", "CVE-2016-5106", "CVE-2016-5107", "CVE-2016-5126", "CVE-2016-5238", "CVE-2016-5337", "CVE-2016-5338", "CVE-2016-5403", "CVE-2016-6258", "CVE-2016-6351");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:05 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-09-07 19:13:27 +0000 (Wed, 07 Sep 2016)");

  script_name("SUSE: Security Advisory (SUSE-SU-2016:2100-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2016:2100-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2016/suse-su-20162100-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/954872");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/955399");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/957986");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/958848");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/961600");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/963161");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/964427");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/967630");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/973188");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/974038");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/974912");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/975130");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/975138");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/975907");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/976058");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/976111");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/978164");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/978295");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/978413");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/979035");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/979620");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/979670");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/980716");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/980724");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/981264");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/981276");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/982024");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/982025");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/982026");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/982224");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/982225");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/982286");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/982695");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/982960");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/983973");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/983984");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/985503");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/986586");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/988675");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/989235");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/990843");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/990923");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2016-August/002217.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xen' package(s) announced via the SUSE-SU-2016:2100-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for xen fixes the several issues.

These security issues were fixed:
- CVE-2014-3672: The qemu implementation in libvirt Xen allowed local guest OS users to cause a denial of service (host disk consumption) by writing to stdout or stderr (bsc#981264).
- CVE-2016-3158: The xrstor function did not properly handle writes to the hardware FSW.ES bit when running on AMD64 processors, which allowed local guest OS users to obtain sensitive register content information from another guest by leveraging pending exception and mask bits (bsc#973188).
- CVE-2016-3159: The fpu_fxrstor function in arch/x86/i387.c did not properly handle writes to the hardware FSW.ES bit when running on AMD64 processors, which allowed local guest OS users to obtain sensitive register content information from another guest by leveraging pending exception and mask bits (bsc#973188).
- CVE-2016-3710: The VGA module improperly performed bounds checking on banked access to video memory, which allowed local guest OS administrators to execute arbitrary code on the host by changing access modes after setting the bank register, aka the 'Dark Portal' issue (bsc#978164).
- CVE-2016-3960: Integer overflow in the x86 shadow pagetable code allowed local guest OS users to cause a denial of service (host crash) or possibly gain privileges by shadowing a superpage mapping (bsc#974038).
- CVE-2016-4001: Buffer overflow in the stellaris_enet_receive function, when the Stellaris ethernet controller is configured to accept large packets, allowed remote attackers to cause a denial of service (QEMU crash) via a large packet (bsc#975130).
- CVE-2016-4002: Buffer overflow in the mipsnet_receive function, when the guest NIC is configured to accept large packets, allowed remote attackers to cause a denial of service (memory corruption and QEMU crash) or possibly execute arbitrary code via a packet larger than 1514 bytes (bsc#975138).
- CVE-2016-4020: The patch_instruction function did not initialize the imm32 variable, which allowed local guest OS administrators to obtain sensitive information from host stack memory by accessing the Task Priority Register (TPR) (bsc#975907).
- CVE-2016-4037: The ehci_advance_state function in hw/usb/hcd-ehci.c allowed local guest OS administrators to cause a denial of service (infinite loop and CPU consumption) via a circular split isochronous transfer descriptor (siTD) list (bsc#976111).
- CVE-2016-4439: The esp_reg_write function in the 53C9X Fast SCSI Controller (FSC) support did not properly check command buffer length, which allowed local guest OS administrators to cause a denial of service (out-of-bounds write and QEMU process crash) or potentially execute arbitrary code on the host via unspecified vectors (bsc#980716).
- CVE-2016-4441: The get_cmd function in the 53C9X Fast SCSI Controller (FSC) support did not properly check DMA length, which allowed local guest OS ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'xen' package(s) on SUSE Linux Enterprise Server 11-SP4, SUSE Linux Enterprise Server for SAP Applications 11-SP4.");

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

if(release == "SLES11.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"xen", rpm:"xen~4.4.4_07~37.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-doc-html", rpm:"xen-doc-html~4.4.4_07~37.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-default", rpm:"xen-kmp-default~4.4.4_07_3.0.101_77~37.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-pae", rpm:"xen-kmp-pae~4.4.4_07_3.0.101_77~37.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs-32bit", rpm:"xen-libs-32bit~4.4.4_07~37.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs", rpm:"xen-libs~4.4.4_07~37.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools", rpm:"xen-tools~4.4.4_07~37.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-domU", rpm:"xen-tools-domU~4.4.4_07~37.1", rls:"SLES11.0SP4"))) {
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
