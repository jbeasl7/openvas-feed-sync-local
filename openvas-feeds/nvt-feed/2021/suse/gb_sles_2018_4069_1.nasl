# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.4069.1");
  script_cve_id("CVE-2017-16533", "CVE-2017-18224", "CVE-2018-10940", "CVE-2018-16658", "CVE-2018-18281", "CVE-2018-18386", "CVE-2018-18445", "CVE-2018-18710", "CVE-2018-19824");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-01-30 13:22:34 +0000 (Wed, 30 Jan 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:4069-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:4069-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20184069-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1051510");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1055120");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1061840");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1065600");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1065729");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1066674");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1067906");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1068273");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1076830");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1078248");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1079524");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1082555");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1082653");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1083647");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1084760");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1084831");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1085535");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1086196");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1089350");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1091800");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1094825");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1095805");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1097755");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1100132");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1103356");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1103925");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1104124");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1104731");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1104824");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1105025");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1105428");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1106105");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1106110");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1106237");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1106240");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1107256");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1107385");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1107866");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1108377");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1108468");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1109330");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1109739");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1109772");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1109806");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1109818");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1109907");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1109911");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1109915");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1109919");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1109951");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1110006");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1110998");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1111040");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1111062");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1111174");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1111506");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1111696");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1111809");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1111921");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1111983");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112128");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112170");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112173");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112208");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112219");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112221");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112246");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112372");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112514");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112554");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112708");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112710");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112711");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112712");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112713");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112731");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112732");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112733");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112734");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112735");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112736");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112738");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112739");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112740");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112741");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112743");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112745");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112746");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112878");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112894");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112899");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112902");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112903");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112905");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112906");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112907");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112963");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1113257");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1113284");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1113295");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1113408");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1113412");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1113501");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1113667");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1113677");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1113722");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1113751");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1113769");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1113780");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1113972");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1114015");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1114178");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1114279");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1114385");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1114576");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1114577");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1114578");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1114579");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1114580");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1114581");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1114582");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1114583");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1114584");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1114585");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1114839");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1115074");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1115269");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1115431");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1115433");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1115440");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1115567");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1115709");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1115976");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1116183");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1116692");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1116693");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1116698");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1116699");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1116700");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1116701");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1116862");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1116863");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1116876");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1116877");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1116878");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1116891");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1116895");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1116899");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1116950");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1117168");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1117172");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1117174");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1117181");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1117184");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1117188");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1117189");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1117349");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1117561");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1117788");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1117789");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1117790");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1117791");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1117792");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1117794");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1117795");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1117796");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1117798");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1117799");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1117801");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1117802");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1117803");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1117804");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1117805");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1117806");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1117807");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1117808");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1117815");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1117816");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1117817");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1117818");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1117819");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1117820");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1117821");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1117822");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1118102");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1118136");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1118137");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1118138");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1118140");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1118152");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1118316");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2018-December/004951.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2018:4069-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP4 kernel was updated to receive various security and bugfixes.

The following security bugs were fixed:

- CVE-2018-19824: A local user could exploit a use-after-free in the ALSA driver by supplying a malicious USB Sound device (with zero interfaces) that is mishandled in usb_audio_probe in sound/usb/card.c (bnc#1118152).
- CVE-2018-18281: The mremap() syscall performs TLB flushes after dropping pagetable locks. If a syscall such as ftruncate() removed entries from the pagetables of a task that is in the middle of mremap(), a stale TLB entry could remain for a short time that permits access to a physical page after it has been released back to the page allocator and reused. (bnc#1113769).
- CVE-2018-18710: An information leak in cdrom_ioctl_select_disc in drivers/cdrom/cdrom.c could be used by local attackers to read kernel memory because a cast from unsigned long to int interferes with bounds checking. This is similar to CVE-2018-10940 and CVE-2018-16658 (bnc#1113751).
- CVE-2018-18445: Faulty computation of numeric bounds in the BPF verifier permitted out-of-bounds memory accesses because adjust_scalar_min_max_vals in kernel/bpf/verifier.c mishandled 32-bit right shifts (bnc#1112372).
- CVE-2018-18386: drivers/tty/n_tty.c allowed local attackers (who are able to access pseudo terminals) to hang/block further usage of any pseudo terminal devices due to an EXTPROC versus ICANON confusion in TIOCINQ (bnc#1094825).
- CVE-2017-18224: fs/ocfs2/aops.c omitted use of a semaphore and consequently had a race condition for access to the extent tree during read operations in DIRECT mode, which allowed local users to cause a denial of service (BUG) by modifying a certain e_cpos field (bnc#1084831).
- CVE-2017-16533: The usbhid_parse function in drivers/hid/usbhid/hid-core.c allowed local users to cause a denial of service (out-of-bounds read and system crash) or possibly have unspecified other impact via a crafted USB device (bnc#1066674).

The following non-security bugs were fixed:

- ACPI/APEI: Handle GSIV and GPIO notification types (bsc#1115567).
- ACPICA: Tables: Add WSMT support (bsc#1089350).
- ACPI/IORT: Fix iort_get_platform_device_domain() uninitialized pointer value (bsc#1051510).
- ACPI / LPSS: Add alternative ACPI HIDs for Cherry Trail DMA controllers (bsc#1051510).
- ACPI, nfit: Fix ARS overflow continuation (bsc#1116895).
- ACPI, nfit: Prefer _DSM over _LSR for namespace label reads (bsc#1112128).
- ACPI/nfit, x86/mce: Handle only uncorrectable machine checks (bsc#1114279).
- ACPI/nfit, x86/mce: Validate a MCE's address before using it (bsc#1114279).
- ACPI / platform: Add SMB0001 HID to forbidden_id_list (bsc#1051510).
- ACPI / processor: Fix the return value of acpi_processor_ids_walk() (bsc#1051510).
- ACPI / watchdog: Prefer iTCO_wdt always when WDAT table uses RTC SRAM (bsc#1051510).
- act_ife: fix a potential use-after-free ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Desktop 12-SP4, SUSE Linux Enterprise Server 12-SP4, SUSE Linux Enterprise Server for SAP Applications 12-SP4.");

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

if(release == "SLES12.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.12.14~95.3.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.12.14~95.3.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.12.14~95.3.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~4.12.14~95.3.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.12.14~95.3.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.12.14~95.3.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.12.14~95.3.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.12.14~95.3.1", rls:"SLES12.0SP4"))) {
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
