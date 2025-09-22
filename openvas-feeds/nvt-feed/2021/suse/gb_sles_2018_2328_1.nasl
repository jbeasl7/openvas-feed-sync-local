# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.2328.1");
  script_cve_id("CVE-2017-18344", "CVE-2018-14734", "CVE-2018-3620", "CVE-2018-3646", "CVE-2018-5390");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-11 13:07:17 +0000 (Thu, 11 Oct 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:2328-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:2328-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20182328-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1012382");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1082653");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1085042");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1085536");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1087081");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1089343");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1090123");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1090435");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1092001");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1094244");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1095643");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1096978");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1097771");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1099858");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1100132");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1100930");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1101658");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1101789");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1102188");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1102197");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1102203");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1102205");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1102207");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1102211");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1102214");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1102215");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1102340");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1102394");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1102683");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1102851");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1103119");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1103580");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1103745");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1103884");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2018-August/004414.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2018:2328-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP3 kernel was updated to 4.4.143 to receive various security and bugfixes.

The following security bugs were fixed:

- CVE-2018-5390 aka 'SegmentSmack': Linux kernel could be forced to make very expensive calls to tcp_collapse_ofo_queue() and tcp_prune_ofo_queue() for every incoming packet which can lead to a denial of service (bnc#1102340).
- CVE-2018-14734: drivers/infiniband/core/ucma.c in the Linux kernel allowed ucma_leave_multicast to access a certain data structure after a cleanup step in ucma_process_join, which allowed attackers to cause a denial of service (use-after-free) (bnc#1103119).
- CVE-2017-18344: The timer_create syscall implementation in kernel/time/posix-timers.c didn't properly validate the sigevent->sigev_notify field, which lead to out-of-bounds access in the show_timer function (called when /proc/$PID/timers is read). This allowed userspace applications to read arbitrary kernel memory (on a kernel built with CONFIG_POSIX_TIMERS and CONFIG_CHECKPOINT_RESTORE) (bnc#1102851 bnc#1103580).
- CVE-2018-3620: Local attackers on baremetal systems could use speculative code patterns on hyperthreaded processors to read data present in the L1 Datacache used by other hyperthreads on the same CPU core, potentially leaking sensitive data. (bnc#1087081).
- CVE-2018-3646: Local attackers in virtualized guest systems could use speculative code patterns on hyperthreaded processors to read data present in the L1 Datacache used by other hyperthreads on the same CPU core, potentially leaking sensitive data, even from other virtual machines or the host system. (bnc#1089343).

The following non-security bugs were fixed:

- Add support for 5,25,50, and 100G to 802.3ad bonding driver (bsc#1096978)
- ahci: Disable LPM on Lenovo 50 series laptops with a too old BIOS (bnc#1012382).
- arm64: do not open code page table entry creation (bsc#1102197).
- arm64: kpti: Use early_param for kpti= command-line option (bsc#1102188).
- arm64: Make sure permission updates happen for pmd/pud (bsc#1102197).
- atm: zatm: Fix potential Spectre v1 (bnc#1012382).
- bcm63xx_enet: correct clock usage (bnc#1012382).
- bcm63xx_enet: do not write to random DMA channel on BCM6345 (bnc#1012382).
- blacklist 9fb8d5dc4b64 ('stop_machine: Disable preemption when waking two stopper threads') Preemption is already disabled inside cpu_stop_queue_two_works() in SLE12-SP3 because it does not have commit 6a19005157c4 ('stop_machine: Do not disable preemption in stop_two_cpus()')
- block: copy ioprio in __bio_clone_fast() (bsc#1082653).
- bpf: fix loading of BPF_MAXINSNS sized programs (bsc#1012382).
- bpf, x64: fix memleak when not converging after image (bsc#1012382).
- cachefiles: Fix missing clear of the CACHEFILES_OBJECT_ACTIVE flag (bsc#1099858).
- cachefiles: Fix refcounting bug in backing-file read monitoring (bsc#1099858).
- cachefiles: Wait rather than BUG'ing on ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"dpdk", rpm:"dpdk~16.11.6~8.7.2", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dpdk-kmp-default", rpm:"dpdk-kmp-default~16.11.6_k4.4.143_94.47~8.7.2", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dpdk-thunderx", rpm:"dpdk-thunderx~16.11.6~8.7.2", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dpdk-thunderx-kmp-default", rpm:"dpdk-thunderx-kmp-default~16.11.6_k4.4.143_94.47~8.7.2", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dpdk-tools", rpm:"dpdk-tools~16.11.6~8.7.2", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.4.143~94.47.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.4.143~94.47.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.4.143~94.47.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~4.4.143~94.47.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.4.143~94.47.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.4.143~94.47.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.4.143~94.47.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.4.143~94.47.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lttng-modules", rpm:"lttng-modules~2.7.1~8.4.2", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lttng-modules-kmp-default", rpm:"lttng-modules-kmp-default~2.7.1_k4.4.143_94.47~8.4.2", rls:"SLES12.0SP3"))) {
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
