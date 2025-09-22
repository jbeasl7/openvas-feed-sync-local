# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.0541.1");
  script_cve_id("CVE-2018-1120", "CVE-2018-16862", "CVE-2018-16884", "CVE-2018-19407", "CVE-2018-19824", "CVE-2018-19985", "CVE-2018-20169", "CVE-2018-5391", "CVE-2018-9568", "CVE-2019-3459", "CVE-2019-3460", "CVE-2019-6974", "CVE-2019-7221", "CVE-2019-7222");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-05 20:40:45 +0000 (Tue, 05 Apr 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:0541-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:0541-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-20190541-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1012382");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1015336");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1015337");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1015340");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1019683");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1019695");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1020413");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1020645");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1023175");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1027260");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1027457");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1031492");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1042286");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1043083");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1046264");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1047487");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1048916");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1050549");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1065600");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1066223");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1068032");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1070805");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1078355");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1079935");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1086095");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1086423");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1086652");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1091405");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1093158");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1094244");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1094823");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1094973");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1096242");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1096281");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1099523");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1099810");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1100105");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1101557");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1102439");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1102660");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1102875");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1102877");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1102879");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1102882");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1102896");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1103097");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1103156");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1103257");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1103624");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1104098");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1104731");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1105428");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1106061");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1106105");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1106237");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1106240");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1106929");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1107385");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1107866");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1108145");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1108240");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1109272");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1109330");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1109695");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1109806");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1110286");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1111062");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1111174");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1111809");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112246");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112963");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1113412");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1113766");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1114190");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1114417");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1114475");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1114648");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1114763");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1114839");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1114871");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1114893");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1115431");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1115433");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1115440");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1115482");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1115709");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1116027");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1116183");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1116285");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1116336");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1116345");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1116497");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1116653");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1116841");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1116924");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1116950");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1116962");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1117108");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1117162");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1117165");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1117186");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1117562");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1117645");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1117744");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1118152");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1118316");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1118319");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1118505");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1118790");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1118798");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1118915");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1118922");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1118926");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1118930");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1118936");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1119204");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1119680");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1119714");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1119877");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1119946");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1119967");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1119970");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1120017");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1120046");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1120722");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1120743");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1120758");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1120902");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1120950");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1121239");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1121240");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1121241");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1121242");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1121275");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1121621");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1121726");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1122650");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1122651");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1122779");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1122885");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1123321");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1123323");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1123357");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1123933");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1124166");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1124728");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1124732");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1124735");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1124775");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1124777");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1124780");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1124811");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1125000");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1125014");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1125446");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1125794");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1125796");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1125808");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1125809");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1125810");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1125892");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/985031");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2019-March/005168.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2019:0541-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP3 kernel was updated to 4.4.175 to receive various security and bugfixes.

The following security bugs were fixed:

- CVE-2019-6974: kvm_ioctl_create_device in virt/kvm/kvm_main.c mishandled reference counting because of a race condition, leading to a use-after-free. (bnc#1124728)
- CVE-2019-7221: Fixed a user-after-free vulnerability in the KVM hypervisor related to the emulation of a preemption timer, allowing an guest user/process to crash the host kernel. (bsc#1124732).
- CVE-2019-7222: Fixed an information leakage in the KVM hypervisor related to handling page fault exceptions, which allowed a guest user/process to use this flaw to leak the host's stack memory contents to a guest (bsc#1124735).
- CVE-2018-1120: By mmap()ing a FUSE-backed file onto a process's memory containing command line arguments (or environment strings), an attacker could have caused utilities from psutils or procps (such as ps, w) or any other program which made a read() call to the /proc/<pid>/cmdline (or /proc/<pid>/environ) files to block indefinitely (denial of service) or for some controlled time (as a synchronization primitive for other attacks) (bnc#1093158).
- CVE-2018-16862: A security flaw was found in a way that the cleancache subsystem clears an inode after the final file truncation (removal). The new file created with the same inode may contain leftover pages from cleancache and the old file data instead of the new one (bnc#1117186).
- CVE-2018-16884: NFS41+ shares mounted in different network namespaces at the same time can make bc_svc_process() use wrong back-channel IDs and cause a use-after-free vulnerability. Thus a malicious container user can cause a host kernel memory corruption and a system panic. Due to the nature of the flaw, privilege escalation cannot be fully ruled out (bnc#1119946).
- CVE-2018-19407: The vcpu_scan_ioapic function in arch/x86/kvm/x86.c allowed local users to cause a denial of service (NULL pointer dereference and BUG) via crafted system calls that reach a situation where ioapic is uninitialized (bnc#1116841).
- CVE-2018-19824: A local user could exploit a use-after-free in the ALSA driver by supplying a malicious USB Sound device (with zero interfaces) that is mishandled in usb_audio_probe in sound/usb/card.c (bnc#1118152).
- CVE-2018-19985: The function hso_probe read if_num from the USB device (as an u8) and used it without a length check to index an array, resulting in an OOB memory read in hso_probe or hso_get_config_data that could be used by local attackers (bnc#1120743).
- CVE-2018-20169: The USB subsystem mishandled size checks during the reading of an extra descriptor, related to __usb_get_extra_descriptor in drivers/usb/core/usb.c (bnc#1119714).
- CVE-2018-5391: The Linux kernel was vulnerable to a denial of service attack with low rates of specially modified packets targeting IP fragment re-assembly. An ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Desktop 12-SP3, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server for SAP Applications 12-SP3.");

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

if(release == "SLES12.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.4.175~94.79.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.4.175~94.79.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.4.175~94.79.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~4.4.175~94.79.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.4.175~94.79.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.4.175~94.79.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.4.175~94.79.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.4.175~94.79.1", rls:"SLES12.0SP3"))) {
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
