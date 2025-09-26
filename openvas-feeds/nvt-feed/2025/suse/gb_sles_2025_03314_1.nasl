# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.03314.1");
  script_cve_id("CVE-2022-50116", "CVE-2024-53177", "CVE-2024-58239", "CVE-2025-38180", "CVE-2025-38323", "CVE-2025-38352", "CVE-2025-38460", "CVE-2025-38498", "CVE-2025-38499", "CVE-2025-38546", "CVE-2025-38555", "CVE-2025-38560", "CVE-2025-38563", "CVE-2025-38608", "CVE-2025-38617", "CVE-2025-38618", "CVE-2025-38644");
  script_tag(name:"creation_date", value:"2025-09-25 04:12:26 +0000 (Thu, 25 Sep 2025)");
  script_version("2025-09-25T05:39:09+0000");
  script_tag(name:"last_modification", value:"2025-09-25 05:39:09 +0000 (Thu, 25 Sep 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:03314-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:03314-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-202503314-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234896");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244824");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245970");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246473");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246911");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1247143");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1247374");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1247518");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1247976");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248223");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248297");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248306");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248312");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248338");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248511");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248614");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248621");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248748");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-September/041815.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2025:03314-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP4 kernel was updated to receive various security bugfixes.


The following security bugs were fixed:

- CVE-2022-50116: kernel: tty: n_gsm: fix deadlock and link starvation in outgoing data path (bsc#1244824).
- CVE-2024-53177: smb: prevent use-after-free due to open_cached_dir error paths (bsc#1234896).
- CVE-2024-58239: tls: stop recv() if initial process_rx_list gave us non-DATA (bsc#1248614).
- CVE-2025-38180: net: atm: fix /proc/net/atm/lec handling (bsc#1245970).
- CVE-2025-38323: net: atm: add lec_mutex (bsc#1246473).
- CVE-2025-38352: posix-cpu-timers: fix race between handle_posix_cpu_timers() and posix_cpu_timer_del() (bsc#1246911).
- CVE-2025-38460: atm: clip: Fix potential null-ptr-deref in to_atmarpd() (bsc#1247143).
- CVE-2025-38498: do_change_type(): refuse to operate on unmounted/not ours mounts (bsc#1247374).
- CVE-2025-38499: clone_private_mnt(): make sure that caller has CAP_SYS_ADMIN in the right userns (bsc#1247976).
- CVE-2025-38546: atm: clip: Fix memory leak of struct clip_vcc (bsc#1248223).
- CVE-2025-38555: usb: gadget : fix use-after-free in composite_dev_cleanup() (bsc#1248297).
- CVE-2025-38560: x86/sev: Evict cache lines during SNP memory validation (bsc#1248312).
- CVE-2025-38563: perf/core: Prevent VMA split of buffer mappings (bsc#1248306).
- CVE-2025-38608: bpf, ktls: Fix data corruption when using bpf_msg_pop_data() in ktls (bsc#1248338).
- CVE-2025-38617: net/packet: fix a race in packet_set_ring() and packet_notifier() (bsc#1248621).
- CVE-2025-38618: vsock: Do not allow binding to VMADDR_PORT_ANY (bsc#1248511).
- CVE-2025-38644: wifi: mac80211: reject TDLS operations when station is not associated (bsc#1248748).

The following non-security bugs were fixed:

- NFSv4.1: fix backchannel max_resp_sz verification check (bsc#1247518).
- Disable N_GSM (jsc#PED-8240).");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 15-SP4, SUSE Linux Enterprise Server for SAP Applications 15-SP4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "SLES15.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb", rpm:"kernel-64kb~5.14.21~150400.24.176.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb-devel", rpm:"kernel-64kb-devel~5.14.21~150400.24.176.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~5.14.21~150400.24.176.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~5.14.21~150400.24.176.1.150400.24.90.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~5.14.21~150400.24.176.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~5.14.21~150400.24.176.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs", rpm:"kernel-docs~5.14.21~150400.24.176.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~5.14.21~150400.24.176.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build", rpm:"kernel-obs-build~5.14.21~150400.24.176.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~5.14.21~150400.24.176.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~5.14.21~150400.24.176.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-zfcpdump", rpm:"kernel-zfcpdump~5.14.21~150400.24.176.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default", rpm:"reiserfs-kmp-default~5.14.21~150400.24.176.1", rls:"SLES15.0SP4"))) {
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
