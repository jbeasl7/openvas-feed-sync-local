# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.01620.1");
  script_cve_id("CVE-2021-47671", "CVE-2022-48933", "CVE-2022-49110", "CVE-2022-49139", "CVE-2022-49741", "CVE-2022-49745", "CVE-2022-49767", "CVE-2023-52928", "CVE-2023-52931", "CVE-2023-52936", "CVE-2023-52937", "CVE-2023-52938", "CVE-2023-52981", "CVE-2023-52982", "CVE-2023-52986", "CVE-2023-52994", "CVE-2023-53001", "CVE-2023-53002", "CVE-2023-53009", "CVE-2023-53014", "CVE-2023-53018", "CVE-2023-53031", "CVE-2023-53051", "CVE-2024-42307", "CVE-2024-46763", "CVE-2024-46865", "CVE-2024-50038", "CVE-2025-21726", "CVE-2025-21785", "CVE-2025-21791", "CVE-2025-21812", "CVE-2025-21839", "CVE-2025-22004", "CVE-2025-22020", "CVE-2025-22045", "CVE-2025-22055", "CVE-2025-22097", "CVE-2025-2312", "CVE-2025-23138", "CVE-2025-39735");
  script_tag(name:"creation_date", value:"2025-05-22 12:07:17 +0000 (Thu, 22 May 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-05-06 16:45:15 +0000 (Tue, 06 May 2025)");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:01620-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:01620-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-202501620-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1054914");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1206843");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1210409");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225903");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229361");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229621");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230764");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231103");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231910");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1236777");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237981");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1238032");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1238471");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1238512");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1238747");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1238865");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1239061");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1239684");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1239968");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240209");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240211");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240214");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240228");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240230");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240246");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240248");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240269");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240271");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240274");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240285");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240295");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240306");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240314");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240315");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240321");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240747");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240835");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1241280");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1241371");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1241421");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1241433");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1241541");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1241625");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1241648");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1242284");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1242493");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1242778");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-May/039286.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2025:01620-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP5 kernel was updated to receive various security bugfixes.


The following security bugs were fixed:

- CVE-2022-48933: netfilter: nf_tables: fix memory leak during stateful obj update (bsc#1229621).
- CVE-2022-49110: netfilter: conntrack: revisit gc autotuning (bsc#1237981).
- CVE-2022-49139: Bluetooth: fix null ptr deref on hci_sync_conn_complete_evt (bsc#1238032).
- CVE-2022-49767: 9p/trans_fd: always use O_NONBLOCK read/write (bsc#1242493).
- CVE-2024-46763: fou: Fix null-ptr-deref in GRO (bsc#1230764).
- CVE-2024-50038: netfilter: xtables: avoid NFPROTO_UNSPEC where needed (bsc#1231910).
- CVE-2025-21726: padata: avoid UAF for reorder_work (bsc#1238865).
- CVE-2025-21785: arm64: cacheinfo: Avoid out-of-bounds write to cacheinfo array (bsc#1238747).
- CVE-2025-21791: vrf: use RCU protection in l3mdev_l3_out() (bsc#1238512).
- CVE-2025-21812: ax25: rcu protect dev->ax25_ptr (bsc#1238471).
- CVE-2025-21839: KVM: x86: Load DR6 with guest value only before entering .vcpu_run() loop (bsc#1239061).
- CVE-2025-22004: net: atm: fix use after free in lec_send() (bsc#1240835).
- CVE-2025-22020: memstick: rtsx_usb_ms: Fix slab-use-after-free in rtsx_usb_ms_drv_remove (bsc#1241280).
- CVE-2025-22045: x86/mm: Fix flush_tlb_range() when used for zapping normal PMDs (bsc#1241433).
- CVE-2025-22055: net: fix geneve_opt length integer overflow (bsc#1241371).
- CVE-2025-22097: drm/vkms: Fix use after free and double free on init error (bsc#1241541).
- CVE-2025-2312: CIFS: New mount option for cifs.upcall namespace resolution (bsc#1239684).
- CVE-2025-23138: watch_queue: fix pipe accounting mismatch (bsc#1241648).
- CVE-2025-39735: jfs: fix slab-out-of-bounds read in ea_get() (bsc#1241625).

The following non-security bugs were fixed:

- cpufreq: ACPI: Mark boost policy as enabled when setting boost (bsc#1236777).
- cpufreq: Allow drivers to advertise boost enabled (bsc#1236777).
- cpufreq: Fix per-policy boost behavior on SoCs using cpufreq_boost_set_sw() (bsc#1236777).
- cpufreq: Support per-policy performance boost (bsc#1236777).
- x86/bhi: Do not set BHI_DIS_S in 32-bit mode (bsc#1242778).
- x86/bpf: Add IBHF call at end of classic BPF (bsc#1242778).
- x86/bpf: Call branch history clearing sequence on exit (bsc#1242778).");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 15-SP5, SUSE Linux Enterprise Server for SAP Applications 15-SP5.");

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

if(release == "SLES15.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"cluster-md-kmp-default", rpm:"cluster-md-kmp-default~5.14.21~150500.55.103.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dlm-kmp-default", rpm:"dlm-kmp-default~5.14.21~150500.55.103.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gfs2-kmp-default", rpm:"gfs2-kmp-default~5.14.21~150500.55.103.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb", rpm:"kernel-64kb~5.14.21~150500.55.103.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb-devel", rpm:"kernel-64kb-devel~5.14.21~150500.55.103.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~5.14.21~150500.55.103.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~5.14.21~150500.55.103.1.150500.6.49.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~5.14.21~150500.55.103.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~5.14.21~150500.55.103.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs", rpm:"kernel-docs~5.14.21~150500.55.103.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~5.14.21~150500.55.103.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build", rpm:"kernel-obs-build~5.14.21~150500.55.103.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~5.14.21~150500.55.103.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~5.14.21~150500.55.103.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-zfcpdump", rpm:"kernel-zfcpdump~5.14.21~150500.55.103.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-kmp-default", rpm:"ocfs2-kmp-default~5.14.21~150500.55.103.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default", rpm:"reiserfs-kmp-default~5.14.21~150500.55.103.1", rls:"SLES15.0SP5"))) {
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
