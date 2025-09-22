# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2016.2528.1");
  script_cve_id("CVE-2014-3615", "CVE-2014-3672", "CVE-2016-3158", "CVE-2016-3159", "CVE-2016-3710", "CVE-2016-3960", "CVE-2016-4001", "CVE-2016-4002", "CVE-2016-4439", "CVE-2016-4441", "CVE-2016-4480", "CVE-2016-5238", "CVE-2016-5338", "CVE-2016-6258", "CVE-2016-7092", "CVE-2016-7094");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:04 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-08-03 17:12:23 +0000 (Wed, 03 Aug 2016)");

  script_name("SUSE: Security Advisory (SUSE-SU-2016:2528-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2016:2528-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2016/suse-su-20162528-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/973188");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/974038");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/975130");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/975138");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/978164");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/978295");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/980716");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/980724");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/981264");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/982960");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/983984");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/988675");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/995785");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/995792");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2016-October/002332.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xen' package(s) announced via the SUSE-SU-2016:2528-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for xen fixes several issues.

These security issues were fixed:
- CVE-2016-7094: Buffer overflow in Xen allowed local x86 HVM guest OS administrators on guests running with shadow paging to cause a denial of service via a pagetable update (bsc#995792)
- CVE-2016-7092: The get_page_from_l3e function in arch/x86/mm.c in Xen allowed local 32-bit PV guest OS administrators to gain host OS privileges via vectors related to L3 recursive pagetables (bsc#995785)
- CVE-2016-6258: The PV pagetable code in arch/x86/mm.c in Xen allowed local 32-bit PV guest OS administrators to gain host OS privileges by leveraging fast-paths for updating pagetable entries (bsc#988675)
- CVE-2016-5338: The (1) esp_reg_read and (2) esp_reg_write functions allowed local guest OS administrators to cause a denial of service (QEMU process crash) or execute arbitrary code on the host via vectors related to the information transfer buffer (bsc#983984)
- CVE-2016-5238: The get_cmd function in hw/scsi/esp.c might have allowed local guest OS administrators to cause a denial of service (out-of-bounds write and QEMU process crash) via vectors related to reading from the information transfer buffer in non-DMA mode (bsc#982960)
- CVE-2014-3672: The qemu implementation in libvirt Xen allowed local guest OS users to cause a denial of service (host disk consumption) by writing to stdout or stderr (bsc#981264)
- CVE-2016-4441: The get_cmd function in the 53C9X Fast SCSI Controller (FSC) support did not properly check DMA length, which allowed local guest OS administrators to cause a denial of service (out-of-bounds write and QEMU process crash) via unspecified vectors, involving an SCSI command (bsc#980724)
- CVE-2016-4439: The esp_reg_write function in the 53C9X Fast SCSI Controller (FSC) support did not properly check command buffer length, which allowed local guest OS administrators to cause a denial of service (out-of-bounds write and QEMU process crash) or potentially execute arbitrary code on the host via unspecified vectors (bsc#980716)
- CVE-2016-3710: The VGA module improperly performed bounds checking on banked access to video memory, which allowed local guest OS administrators to execute arbitrary code on the host by changing access modes after setting the bank register, aka the 'Dark Portal' issue (bsc#978164)
- CVE-2016-4480: The guest_walk_tables function in arch/x86/mm/guest_walk.c in Xen did not properly handle the Page Size (PS) page table entry bit at the L4 and L3 page table levels, which might have allowed local guest OS users to gain privileges via a crafted mapping of memory (bsc#978295)
- CVE-2016-3960: Integer overflow in the x86 shadow pagetable code allowed local guest OS users to cause a denial of service (host crash) or possibly gain privileges by shadowing a superpage mapping (bsc#974038)
- CVE-2016-3158: The xrstor function did not properly handle writes to the hardware ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'xen' package(s) on SUSE Linux Enterprise Server 11-SP2.");

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

if(release == "SLES11.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"xen", rpm:"xen~4.1.6_08~29.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-devel", rpm:"xen-devel~4.1.6_08~29.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-doc-html", rpm:"xen-doc-html~4.1.6_08~29.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-doc-pdf", rpm:"xen-doc-pdf~4.1.6_08~29.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-default", rpm:"xen-kmp-default~4.1.6_08_3.0.101_0.7.40~29.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-pae", rpm:"xen-kmp-pae~4.1.6_08_3.0.101_0.7.40~29.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-trace", rpm:"xen-kmp-trace~4.1.6_08_3.0.101_0.7.40~29.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs-32bit", rpm:"xen-libs-32bit~4.1.6_08~29.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs", rpm:"xen-libs~4.1.6_08~29.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools", rpm:"xen-tools~4.1.6_08~29.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-domU", rpm:"xen-tools-domU~4.1.6_08~29.1", rls:"SLES11.0SP2"))) {
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
