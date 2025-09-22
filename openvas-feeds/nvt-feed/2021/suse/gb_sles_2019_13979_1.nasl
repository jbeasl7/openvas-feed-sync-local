# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.13979.1");
  script_cve_id("CVE-2016-10741", "CVE-2017-18360", "CVE-2018-19407", "CVE-2018-19824", "CVE-2018-19985", "CVE-2018-20169", "CVE-2018-9568", "CVE-2019-7222");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:30 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-12-31 15:23:42 +0000 (Mon, 31 Dec 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:13979-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0|SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:13979-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-201913979-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1012382");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1031572");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1068032");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1086695");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1087081");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1094244");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1098658");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1104098");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1104367");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1104684");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1104818");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1105536");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1106105");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1106886");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1107371");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1109330");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1109806");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1110006");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112963");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1113667");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1114440");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1114672");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1114920");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1115007");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1115038");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1115827");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1115828");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1115829");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1115830");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1115831");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1115832");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1115833");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1115834");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1115835");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1115836");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1115837");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1115838");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1115839");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1115840");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1115841");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1115842");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1115843");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1115844");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1116841");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1117796");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1117802");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1117805");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1117806");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1117943");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1118152");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1118319");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1118760");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1119255");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1119714");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1120056");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1120077");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1120086");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1120093");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1120094");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1120105");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1120107");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1120109");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1120217");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1120223");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1120226");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1120336");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1120347");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1120743");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1120950");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1121872");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1121997");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1122874");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1123505");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1123702");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1123706");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1124010");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1124735");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1125931");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/931850");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/969471");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/969473");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2019-March/005194.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2019:13979-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 11 SP4 kernel was updated to receive various security and bugfixes.

The following security bugs were fixed:

- CVE-2016-10741: fs/xfs/xfs_aops.c allowed local users to cause a denial of service (system crash) because there is a race condition between direct and memory-mapped I/O (associated with a hole) that is handled with BUG_ON instead of an I/O failure (bnc#1114920 bnc#1124010).
- CVE-2017-18360: In change_port_settings in drivers/usb/serial/io_ti.c local users could cause a denial of service by division-by-zero in the serial device layer by trying to set very high baud rates (bnc#1123706).
- CVE-2018-9568: In sk_clone_lock of sock.c, there is a possible memory corruption due to type confusion. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation. (bnc#1118319).
- CVE-2018-19407: The vcpu_scan_ioapic function in arch/x86/kvm/x86.c allowed local users to cause a denial of service (NULL pointer dereference and BUG) via crafted system calls that reach a situation where ioapic is uninitialized (bnc#1116841).
- CVE-2018-19824: A local user could exploit a use-after-free in the ALSA driver by supplying a malicious USB Sound device (with zero interfaces) that is mishandled in usb_audio_probe in sound/usb/card.c (bnc#1118152).
- CVE-2018-19985: The function hso_probe read if_num from the USB device (as an u8) and used it without a length check to index an array, resulting in an OOB memory read in hso_probe or hso_get_config_data that could be used by local attackers (bnc#1120743).
- CVE-2018-20169: The USB subsystem mishandled size checks during the reading of an extra descriptor, related to __usb_get_extra_descriptor in drivers/usb/core/usb.c (bnc#1119714).
- CVE-2019-7222: A information leak in exception handling in KVM could be used to expose host memory to guests. (bnc#1124735).

The following non-security bugs were fixed:

- aacraid: Fix memory leak in aac_fib_map_free (bsc#1115827).
- arcmsr: upper 32 of dma address lost (bsc#1115828).
- block/swim3: Fix -EBUSY error when re-opening device after unmount (bsc#1121997).
- block/swim: Fix array bounds check (Git-fix).
- btrfs: Enhance btrfs_trim_fs function to handle error better (Dependency for bsc#1113667).
- btrfs: Ensure btrfs_trim_fs can trim the whole filesystem (bsc#1113667).
- cpusets, isolcpus: exclude isolcpus from load balancing in cpusets (bsc#1119255).
- dasd: fix deadlock in dasd_times_out (bnc#1117943, LTC#174111).
- drivers: hv: vmbus: check the creation_status in vmbus_establish_gpadl() (bsc#1104098).
- drm/ast: Remove existing framebuffers before loading driver (boo#1112963)
- drm/fb-helper: Ignore the value of fb_var_screeninfo.pixclock (bsc#1106886)
- ext4: add missing brelse() update_backups()'s error path (bsc#1117796).
- ext4: avoid buffer leak in ext4_orphan_add() after prior ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 11-SP4, SUSE Linux Enterprise Server for SAP Applications 11-SP4.");

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

if(release == "SLES11.0") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-extra", rpm:"kernel-default-extra~3.0.101~108.87.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae-extra", rpm:"kernel-pae-extra~3.0.101~108.87.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64-extra", rpm:"kernel-ppc64-extra~3.0.101~108.87.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-extra", rpm:"kernel-trace-extra~3.0.101~108.87.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-extra", rpm:"kernel-xen-extra~3.0.101~108.87.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES11.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-bigmem", rpm:"kernel-bigmem~3.0.101~108.87.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-bigmem-base", rpm:"kernel-bigmem-base~3.0.101~108.87.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-bigmem-devel", rpm:"kernel-bigmem-devel~3.0.101~108.87.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~3.0.101~108.87.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~3.0.101~108.87.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~3.0.101~108.87.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~3.0.101~108.87.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2", rpm:"kernel-ec2~3.0.101~108.87.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-base", rpm:"kernel-ec2-base~3.0.101~108.87.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-devel", rpm:"kernel-ec2-devel~3.0.101~108.87.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae", rpm:"kernel-pae~3.0.101~108.87.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae-base", rpm:"kernel-pae-base~3.0.101~108.87.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae-devel", rpm:"kernel-pae-devel~3.0.101~108.87.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64", rpm:"kernel-ppc64~3.0.101~108.87.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64-base", rpm:"kernel-ppc64-base~3.0.101~108.87.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64-devel", rpm:"kernel-ppc64-devel~3.0.101~108.87.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~3.0.101~108.87.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~3.0.101~108.87.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace", rpm:"kernel-trace~3.0.101~108.87.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-base", rpm:"kernel-trace-base~3.0.101~108.87.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-devel", rpm:"kernel-trace-devel~3.0.101~108.87.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~3.0.101~108.87.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-base", rpm:"kernel-xen-base~3.0.101~108.87.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~3.0.101~108.87.1", rls:"SLES11.0SP4"))) {
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
