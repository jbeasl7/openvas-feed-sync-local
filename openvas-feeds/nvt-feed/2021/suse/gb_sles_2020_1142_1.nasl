# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.1142.1");
  script_cve_id("CVE-2018-20836", "CVE-2019-19768", "CVE-2019-19770", "CVE-2019-3701", "CVE-2019-9458", "CVE-2020-10942", "CVE-2020-11494", "CVE-2020-11669", "CVE-2020-2732", "CVE-2020-8647", "CVE-2020-8649", "CVE-2020-8834", "CVE-2020-9383");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-03-24 15:17:56 +0000 (Tue, 24 Mar 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:1142-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:1142-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20201142-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1044231");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1050549");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1051510");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1051858");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1056686");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1060463");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1065600");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1065729");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1083647");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1085030");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1088810");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1103990");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1103992");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1104353");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1104745");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1104967");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1109837");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1109911");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1111666");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1111974");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112178");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112374");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112504");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1113956");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1114279");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1114685");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1118338");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1119680");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1120386");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1123328");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1127611");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1133021");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1134090");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1134395");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1136157");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1136333");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1137325");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1141895");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1142685");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1144162");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1144333");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1145051");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1145929");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1146539");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1148868");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1154385");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1156510");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1157424");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1158187");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1158552");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1158983");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1159037");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1159142");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1159198");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1159199");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1159285");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1160659");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1161561");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1161702");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1161951");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1162171");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1162929");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1162931");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1163403");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1163508");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1163762");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1163897");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1163971");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1164051");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1164078");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1164115");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1164284");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1164388");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1164471");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1164507");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1164598");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1164632");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1164705");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1164712");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1164727");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1164728");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1164729");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1164730");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1164731");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1164732");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1164733");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1164734");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1164735");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1164777");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1164780");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1164893");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1165019");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1165111");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1165182");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1165185");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1165211");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1165404");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1165488");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1165527");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1165581");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1165741");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1165813");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1165823");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1165873");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1165929");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1165949");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1165950");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1165980");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1165984");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1165985");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1166003");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1166101");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1166102");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1166103");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1166104");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1166632");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1166658");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1166730");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1166731");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1166732");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1166733");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1166734");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1166735");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1166780");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1166860");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1166861");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1166862");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1166864");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1166866");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1166867");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1166868");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1166870");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1166940");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1166982");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1167005");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1167216");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1167288");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1167290");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1167316");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1167421");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1167423");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1167627");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1167629");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1168075");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1168202");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1168273");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1168276");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1168295");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1168367");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1168424");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1168443");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1168486");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1168552");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1168760");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1168762");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1168763");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1168764");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1168765");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1168829");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1168854");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1168881");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1168884");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1168952");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1169013");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1169057");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1169307");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1169308");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1169390");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1169514");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1169625");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2020-April/006756.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2020:1142-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP5 kernel was updated to receive various security and bugfixes.

The following security bugs were fixed:

- CVE-2020-8834: KVM on Power8 processors had a conflicting use of HSTATE_HOST_R1 to store r1 state in kvmppc_hv_entry plus in kvmppc_{save,restore}_tm, leading to a stack corruption. Because of this, an attacker with the ability to run code in kernel space of a guest VM can cause the host kernel to panic (bnc#1168276).
- CVE-2020-11494: An issue was discovered in slc_bump in drivers/net/can/slcan.c, which allowed attackers to read uninitialized can_frame data, potentially containing sensitive information from kernel stack memory, if the configuration lacks CONFIG_INIT_STACK_ALL (bnc#1168424).
- CVE-2020-10942: In get_raw_socket in drivers/vhost/net.c lacks validation of an sk_family field, which might allow attackers to trigger kernel stack corruption via crafted system calls (bnc#1167629).
- CVE-2019-9458: In the video driver there was a use after free due to a race condition. This could lead to local escalation of privilege with no additional execution privileges needed (bnc#1168295).
- CVE-2019-3701: Fixed an issue in can_can_gw_rcv, which could cause a system crash (bnc#1120386).
- CVE-2019-19770: Fixed a use-after-free in the debugfs_remove function (bsc#1159198).
- CVE-2020-11669: Fixed an issue where arch/powerpc/kernel/idle_book3s.S did not have save/restore functionality for PNV_POWERSAVE_AMR, PNV_POWERSAVE_UAMOR, and PNV_POWERSAVE_AMOR (bnc#1169390).
- CVE-2020-2732: Fixed an issue where under some circumstances, an L2 guest may trick the L0 guest into accessing sensitive L1 resources that should be inaccessible to the L2 guest (bnc#1163971).
- CVE-2020-8647: There was a use-after-free vulnerability in the vc_do_resize function in drivers/tty/vt/vt.c (bnc#1162929 1164078).
- CVE-2020-8649: There was a use-after-free vulnerability in the vgacon_invert_region function in drivers/video/console/vgacon.c (bnc#1162929 1162931).
- CVE-2020-9383: An issue was discovered set_fdc in drivers/block/floppy.c leads to a wait_til_ready out-of-bounds read because the FDC index is not checked for errors before assigning it (bnc#1165111).
- CVE-2019-19768: Fixed a use-after-free in the __blk_add_trace function in kernel/trace/blktrace.c (bnc#1159285).
- CVE-2018-20836: Fixed an issue where a race condition in smp_task_timedout() and smp_task_done() cloud lead to a use-after-free (bnc#1134395).

The following non-security bugs were fixed:

- ACPICA: Introduce ACPI_ACCESS_BYTE_WIDTH() macro (bsc#1051510).
- ACPI: watchdog: Fix gas->access_width usage (bsc#1051510).
- ahci: Add support for Amazon's Annapurna Labs SATA controller (bsc#1169013).
- ALSA: ali5451: remove redundant variable capture_flag (bsc#1051510).
- ALSA: core: Add snd_device_get_state() helper (bsc#1051510).
- ALSA: core: Replace zero-length array with flexible-array member ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server for SAP Applications 12-SP5.");

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

if(release == "SLES12.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.12.14~122.20.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.12.14~122.20.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.12.14~122.20.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~4.12.14~122.20.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.12.14~122.20.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.12.14~122.20.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.12.14~122.20.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.12.14~122.20.1", rls:"SLES12.0SP5"))) {
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
