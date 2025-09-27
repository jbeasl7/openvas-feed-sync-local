# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.03344.1");
  script_cve_id("CVE-2022-49980", "CVE-2022-50116", "CVE-2023-53117", "CVE-2024-42265", "CVE-2024-53093", "CVE-2024-53177", "CVE-2024-57947", "CVE-2024-58239", "CVE-2025-21701", "CVE-2025-21971", "CVE-2025-37798", "CVE-2025-38088", "CVE-2025-38120", "CVE-2025-38177", "CVE-2025-38180", "CVE-2025-38184", "CVE-2025-38323", "CVE-2025-38350", "CVE-2025-38352", "CVE-2025-38460", "CVE-2025-38468", "CVE-2025-38477", "CVE-2025-38494", "CVE-2025-38495", "CVE-2025-38497", "CVE-2025-38498", "CVE-2025-38499", "CVE-2025-38546", "CVE-2025-38555", "CVE-2025-38560", "CVE-2025-38563", "CVE-2025-38608", "CVE-2025-38617", "CVE-2025-38618", "CVE-2025-38644");
  script_tag(name:"creation_date", value:"2025-09-25 15:06:07 +0000 (Thu, 25 Sep 2025)");
  script_version("2025-09-26T05:38:41+0000");
  script_tag(name:"last_modification", value:"2025-09-26 05:38:41 +0000 (Fri, 26 Sep 2025)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-12-24 15:02:22 +0000 (Tue, 24 Dec 2024)");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:03344-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:03344-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-202503344-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229334");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233640");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234896");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1236333");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237164");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240799");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1242414");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1242780");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244309");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244824");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245110");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245506");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245711");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245956");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245970");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245986");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246211");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246473");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246781");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246911");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1247143");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1247314");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1247347");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1247348");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1247349");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1247374");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1247437");
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
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249353");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-September/041838.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2025:03344-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP5 kernel was updated to receive various security bugfixes.


The following security bugs were fixed:

- CVE-2022-49980: USB: gadget: fix use-after-free read in usb_udc_uevent() (bsc#1245110).
- CVE-2022-50116: kernel: tty: n_gsm: fix deadlock and link starvation in outgoing data path (bsc#1244824).
- CVE-2023-53117: fs: prevent out-of-bounds array speculation when closing a file descriptor (bsc#1242780).
- CVE-2024-42265: protect the fetch of ->fd[fd] in do_dup2() from mispredictions (bsc#1229334).
- CVE-2024-53093: nvme-multipath: defer partition scanning (bsc#1233640).
- CVE-2024-53177: smb: prevent use-after-free due to open_cached_dir error paths (bsc#1234896).
- CVE-2024-58239: tls: stop recv() if initial process_rx_list gave us non-DATA (bsc#1248614).
- CVE-2025-21701: net: avoid race between device unregistration and ethnl ops (bsc#1237164).
- CVE-2025-21971: net_sched: Prevent creation of classes with TC_H_ROOT (bsc#1240799).
- CVE-2025-38180: net: atm: fix /proc/net/atm/lec handling (bsc#1245970).
- CVE-2025-38184: tipc: fix null-ptr-deref when acquiring remote ip of ethernet bearer (bsc#1245956).
- CVE-2025-38323: net: atm: add lec_mutex (bsc#1246473).
- CVE-2025-38350: net/sched: Always pass notifications when child class becomes empty (bsc#1246781).
- CVE-2025-38352: posix-cpu-timers: fix race between handle_posix_cpu_timers() and posix_cpu_timer_del() (bsc#1246911).
- CVE-2025-38460: atm: clip: Fix potential null-ptr-deref in to_atmarpd() (bsc#1247143).
- CVE-2025-38468: net/sched: Return NULL when htb_lookup_leaf encounters an empty rbtree (bsc#1247437).
- CVE-2025-38477: net/sched: sch_qfq: Fix race condition on qfq_aggregate (bsc#1247314).
- CVE-2025-38494: HID: core: do not bypass hid_hw_raw_request (bsc#1247349).
- CVE-2025-38495: HID: core: ensure the allocated report buffer can contain the reserved report ID (bsc#1247348).
- CVE-2025-38497: usb: gadget: configfs: Fix OOB read on empty string write (bsc#1247347).
- CVE-2025-38498: do_change_type(): refuse to operate on unmounted/not ours mounts (bsc#1247374).
- CVE-2025-38499: clone_private_mnt(): make sure that caller has CAP_SYS_ADMIN in the right userns (bsc#1247976).
- CVE-2025-38546: atm: clip: Fix memory leak of struct clip_vcc (bsc#1248223).
- CVE-2025-38555: usb: gadget : fix use-after-free in composite_dev_cleanup() (bsc#1248297).
- CVE-2025-38560: x86/sev: Evict cache lines during SNP memory validation (bsc#1248312).
- CVE-2025-38563: perf/core: Prevent VMA split of buffer mappings (bsc#1248306).
- CVE-2025-38608: bpf, ktls: Fix data corruption when using bpf_msg_pop_data() in ktls (bsc#1248338).
- CVE-2025-38617: net/packet: fix a race in packet_set_ring() and packet_notifier() (bsc#1248621).
- CVE-2025-38618: vsock: Do not allow binding to VMADDR_PORT_ANY (bsc#1248511).
- CVE-2025-38644: wifi: mac80211: reject TDLS operations when station is not associated ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 15-SP5, SUSE Linux Enterprise Server for SAP Applications 15-SP5.");

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

if(release == "SLES15.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"cluster-md-kmp-default", rpm:"cluster-md-kmp-default~5.14.21~150500.55.121.2", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dlm-kmp-default", rpm:"dlm-kmp-default~5.14.21~150500.55.121.2", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gfs2-kmp-default", rpm:"gfs2-kmp-default~5.14.21~150500.55.121.2", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb", rpm:"kernel-64kb~5.14.21~150500.55.121.2", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb-devel", rpm:"kernel-64kb-devel~5.14.21~150500.55.121.2", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~5.14.21~150500.55.121.2", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~5.14.21~150500.55.121.2.150500.6.57.2", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~5.14.21~150500.55.121.2", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~5.14.21~150500.55.121.2", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs", rpm:"kernel-docs~5.14.21~150500.55.121.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~5.14.21~150500.55.121.2", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build", rpm:"kernel-obs-build~5.14.21~150500.55.121.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~5.14.21~150500.55.121.2", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~5.14.21~150500.55.121.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-zfcpdump", rpm:"kernel-zfcpdump~5.14.21~150500.55.121.2", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-kmp-default", rpm:"ocfs2-kmp-default~5.14.21~150500.55.121.2", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default", rpm:"reiserfs-kmp-default~5.14.21~150500.55.121.2", rls:"SLES15.0SP5"))) {
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
