# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2024.2495.1");
  script_cve_id("CVE-2021-47555", "CVE-2021-47571", "CVE-2023-24023", "CVE-2023-52670", "CVE-2023-52752", "CVE-2023-52837", "CVE-2023-52846", "CVE-2023-52881", "CVE-2024-26745", "CVE-2024-26923", "CVE-2024-35789", "CVE-2024-35861", "CVE-2024-35862", "CVE-2024-35864", "CVE-2024-35869", "CVE-2024-35950", "CVE-2024-36894", "CVE-2024-36899", "CVE-2024-36904", "CVE-2024-36940", "CVE-2024-36964", "CVE-2024-36971", "CVE-2024-38541", "CVE-2024-38545", "CVE-2024-38559", "CVE-2024-38560", "CVE-2024-38564", "CVE-2024-38578", "CVE-2024-38610");
  script_tag(name:"creation_date", value:"2025-02-13 14:53:48 +0000 (Thu, 13 Feb 2025)");
  script_version("2025-09-18T05:38:39+0000");
  script_tag(name:"last_modification", value:"2025-09-18 05:38:39 +0000 (Thu, 18 Sep 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-09-17 17:05:59 +0000 (Wed, 17 Sep 2025)");

  script_name("SUSE: Security Advisory (SUSE-SU-2024:2495-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:2495-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20242495-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1195775");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1216124");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218148");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219224");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220492");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222015");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222254");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222678");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223384");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224020");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224679");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224696");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224703");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224749");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224764");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224765");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224766");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224935");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225098");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225467");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225487");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225518");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225611");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225732");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225737");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225749");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225840");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225866");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226145");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226211");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226212");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226270");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226587");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226595");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226634");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226758");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226785");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226786");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226789");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226953");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226962");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2024-July/018982.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2024:2495-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP4 kernel was updated to receive various security bugfixes.


The following security bugs were fixed:

- CVE-2023-52846: hsr: Prevent use after free in prp_create_tagged_frame() (bsc#1225098).
- CVE-2024-36904: tcp: Use refcount_inc_not_zero() in tcp_twsk_unique() (bsc#1225732).
- CVE-2023-52881: tcp: do not accept ACK of bytes we never sent (bsc#1225611).
- CVE-2024-35869: smb: client: guarantee refcounted children from parent session (bsc#1224679).
- CVE-2024-38564: bpf: Add BPF_PROG_TYPE_CGROUP_SKB attach type enforcement in BPF_LINK_CREATE (bsc#1226789).
- CVE-2024-38559: scsi: qedf: Ensure the copied buf is NUL terminated (bsc#1226785).
- CVE-2024-38560: scsi: bfa: Ensure the copied buf is NUL terminated (bsc#1226786).
- CVE-2024-38578: ecryptfs: Fix buffer size for tag 66 packet (bsc#1226634,).
- CVE-2024-38545: RDMA/hns: Fix UAF for cq async event (bsc#1226595)
- CVE-2023-52837: nbd: fix uaf in nbd_open (bsc#1224935).
- CVE-2024-38541: of: module: add buffer overflow check in of_modalias() (bsc#1226587).
- CVE-2024-36971: net: fix __dst_negative_advice() race (bsc#1226145).
- CVE-2024-35864: Fixed potential UAF in smb2_is_valid_lease_break() (bsc#1224765).
- CVE-2024-35862: Fixed potential UAF in smb2_is_network_name_deleted() (bsc#1224764).
- CVE-2024-38610: drivers/virt/acrn: fix PFNMAP PTE checks in acrn_vm_ram_map() (bsc#1226758).
- CVE-2024-35861: Fixed potential UAF in cifs_signal_cifsd_for_reconnect()(bsc#1224766).
- CVE-2023-52752: smb: client: fix use-after-free bug in cifs_debug_data_proc_show() (bsc#1225487).
- CVE-2024-36899: gpiolib: cdev: Fix use after free in lineinfo_changed_notify (bsc#1225737).
- CVE-2023-52670: rpmsg: virtio: Free driver_override when rpmsg_remove() (bsc#1224696).
- CVE-2024-35789: Check fast rx for non-4addr sta VLAN changes (bsc#1224749).
- CVE-2024-36964: fs/9p: only translate RWX permissions for plain 9P2000 (bsc#1225866).
- CVE-2024-36940: pinctrl: core: delete incorrect free in pinctrl_enable() (bsc#1225840).
- CVE-2021-47571: staging: rtl8192e: Fix use after free in _rtl92e_pci_disconnect() (bsc#1225518).
- CVE-2021-47555: net: vlan: fix underflow for the real_dev refcnt (bsc#1225467).
- CVE-2023-24023: Bluetooth: Add more enc key size check (bsc#1218148).
- CVE-2024-36894: usb: gadget: f_fs: Fix race between aio_cancel() and AIO request complete (bsc#1225749).
- CVE-2024-35950: drm/client: Fully protect modes with dev->mode_config.mutex (bsc#1224703).
- CVE-2024-26923: Fixed false-positive lockdep splat for spin_lock() in __unix_gc() (bsc#1223384).

The following non-security bugs were fixed:

- Revert 'build initrd without systemd' (bsc#1195775)'
- cgroup: Add annotation for holding namespace_sem in current_cgns_cgroup_from_root() (bsc#1222254).
- cgroup: Eliminate the need for cgroup_mutex in proc_cgroup_show() (bsc#1222254).
- cgroup: Make operations on the cgroup root_list RCU safe ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb", rpm:"kernel-64kb~5.14.21~150400.24.125.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb-devel", rpm:"kernel-64kb-devel~5.14.21~150400.24.125.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~5.14.21~150400.24.125.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~5.14.21~150400.24.125.1.150400.24.60.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~5.14.21~150400.24.125.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~5.14.21~150400.24.125.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs", rpm:"kernel-docs~5.14.21~150400.24.125.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~5.14.21~150400.24.125.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build", rpm:"kernel-obs-build~5.14.21~150400.24.125.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~5.14.21~150400.24.125.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~5.14.21~150400.24.125.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-zfcpdump", rpm:"kernel-zfcpdump~5.14.21~150400.24.125.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default", rpm:"reiserfs-kmp-default~5.14.21~150400.24.125.1", rls:"SLES15.0SP4"))) {
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
