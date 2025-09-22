# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2024.2365.1");
  script_cve_id("CVE-2020-10135", "CVE-2021-3896", "CVE-2021-43389", "CVE-2021-4439", "CVE-2021-47247", "CVE-2021-47311", "CVE-2021-47328", "CVE-2021-47368", "CVE-2021-47372", "CVE-2021-47379", "CVE-2021-47571", "CVE-2021-47583", "CVE-2022-0435", "CVE-2022-22942", "CVE-2022-2938", "CVE-2022-48711", "CVE-2022-48760", "CVE-2022-48771", "CVE-2023-24023", "CVE-2023-52707", "CVE-2023-52752", "CVE-2023-52881", "CVE-2024-26921", "CVE-2024-26923", "CVE-2024-35789", "CVE-2024-35861", "CVE-2024-35862", "CVE-2024-35864", "CVE-2024-35878", "CVE-2024-35950", "CVE-2024-36894", "CVE-2024-36904", "CVE-2024-36940", "CVE-2024-36964", "CVE-2024-38541", "CVE-2024-38545", "CVE-2024-38559", "CVE-2024-38560");
  script_tag(name:"creation_date", value:"2025-02-13 14:53:48 +0000 (Thu, 13 Feb 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-07 19:43:55 +0000 (Thu, 07 Apr 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2024:2365-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:2365-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20242365-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1171988");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1191958");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1195065");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1195254");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1202623");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218148");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219224");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222015");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223138");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223384");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224671");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224703");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224749");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224764");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224765");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224766");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224865");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225010");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225047");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225109");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225161");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225184");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225203");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225487");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225518");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225611");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225732");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225749");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225840");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225866");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226563");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226587");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226595");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226670");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226672");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226712");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226732");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226758");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226786");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226962");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2024-July/035864.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2024:2365-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP2 kernel was updated to receive various security bugfixes.


The following security bugs were fixed:

- CVE-2021-47247: net/mlx5e: Fix use-after-free of encap entry in neigh update handler (bsc#1224865).
- CVE-2021-47311: net: qcom/emac: fix UAF in emac_remove (bsc#1225010).
- CVE-2021-47368: enetc: Fix illegal access when reading affinity_hint (bsc#1225161).
- CVE-2021-47372: net: macb: fix use after free on rmmod (bsc#1225184).
- CVE-2021-47379: blk-cgroup: fix UAF by grabbing blkcg lock before destroying blkg pd (bsc#1225203).
- CVE-2021-47571: staging: rtl8192e: Fix use after free in _rtl92e_pci_disconnect() (bsc#1225518).
- CVE-2022-2938: psi: Fix uaf issue when psi trigger is destroyed while being polled (bsc#1202623).
- CVE-2022-48760: USB: core: Fix hang in usb_kill_urb by adding memory barriers (bsc#1226712).
- CVE-2023-52707: sched/psi: Fix use-after-free in ep_remove_wait_queue() (bsc#1225109).
- CVE-2023-52752: smb: client: fix use-after-free bug in cifs_debug_data_proc_show() (bsc#1225487).
- CVE-2023-52881: tcp: do not accept ACK of bytes we never sent (bsc#1225611).
- CVE-2024-26921: Preserve kabi for sk_buff (bsc#1223138).
- CVE-2024-26923: Fixed false-positive lockdep splat for spin_lock() in __unix_gc() (bsc#1223384).
- CVE-2024-35789: Check fast rx for non-4addr sta VLAN changes (bsc#1224749).
- CVE-2024-35861: Fixed potential UAF in cifs_signal_cifsd_for_reconnect() (bsc#1224766).
- CVE-2024-35862: Fixed potential UAF in smb2_is_network_name_deleted() (bsc#1224764).
- CVE-2024-35864: Fixed potential UAF in smb2_is_valid_lease_break() (bsc#1224765).
- CVE-2024-35950: drm/client: Fully protect modes with dev->mode_config.mutex (bsc#1224703).
- CVE-2024-36894: usb: gadget: f_fs: Fix race between aio_cancel() and AIO request complete (bsc#1225749).
- CVE-2024-36904: tcp: Use refcount_inc_not_zero() in tcp_twsk_unique() (bsc#1225732).
- CVE-2024-36940: pinctrl: core: delete incorrect free in pinctrl_enable() (bsc#1225840).
- CVE-2024-36964: fs/9p: only translate RWX permissions for plain 9P2000 (bsc#1225866).
- CVE-2024-38545: RDMA/hns: Fix UAF for cq async event (bsc#1226595)
- CVE-2024-38559: scsi: qedf: Ensure the copied buf is NUL terminated (bsc#1226758).
- CVE-2024-38560: scsi: bfa: Ensure the copied buf is NUL terminated (bsc#1226786).

The following non-security bugs were fixed:

- ocfs2: adjust enabling place for la window (bsc#1219224).
- ocfs2: fix sparse warnings (bsc#1219224).
- ocfs2: improve write IO performance when fragmentation is high (bsc#1219224).
- ocfs2: speed up chain-list searching (bsc#1219224).
- x86/tsc: Trust initial offset in architectural TSC-adjust MSRs (bsc#1222015 bsc#1226962).
- x86/xen: Drop USERGS_SYSRET64 paravirt call (git-fixes).");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 15-SP2, SUSE Linux Enterprise Server for SAP Applications 15-SP2.");

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

if(release == "SLES15.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~5.3.18~150200.24.197.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~5.3.18~150200.24.197.1.150200.9.101.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~5.3.18~150200.24.197.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~5.3.18~150200.24.197.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs", rpm:"kernel-docs~5.3.18~150200.24.197.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~5.3.18~150200.24.197.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build", rpm:"kernel-obs-build~5.3.18~150200.24.197.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt", rpm:"kernel-preempt~5.3.18~150200.24.197.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt-devel", rpm:"kernel-preempt-devel~5.3.18~150200.24.197.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~5.3.18~150200.24.197.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~5.3.18~150200.24.197.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default", rpm:"reiserfs-kmp-default~5.3.18~150200.24.197.1", rls:"SLES15.0SP2"))) {
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
