# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.02846.1");
  script_cve_id("CVE-2021-46984", "CVE-2021-46987", "CVE-2022-4129", "CVE-2022-49138", "CVE-2022-49319", "CVE-2022-49323", "CVE-2022-49768", "CVE-2022-49825", "CVE-2022-49934", "CVE-2022-49948", "CVE-2022-49969", "CVE-2022-49993", "CVE-2022-50025", "CVE-2022-50027", "CVE-2022-50030", "CVE-2022-50033", "CVE-2022-50103", "CVE-2022-50149", "CVE-2022-50226", "CVE-2023-2176", "CVE-2023-52878", "CVE-2023-53020", "CVE-2023-53117", "CVE-2023-53118", "CVE-2024-26974", "CVE-2024-26982", "CVE-2024-44963", "CVE-2024-46713", "CVE-2024-49861", "CVE-2025-21731", "CVE-2025-21928", "CVE-2025-23163", "CVE-2025-37798", "CVE-2025-37856", "CVE-2025-37885", "CVE-2025-37920", "CVE-2025-38034", "CVE-2025-38035", "CVE-2025-38040", "CVE-2025-38051", "CVE-2025-38058", "CVE-2025-38064", "CVE-2025-38068", "CVE-2025-38074", "CVE-2025-38079", "CVE-2025-38094", "CVE-2025-38105", "CVE-2025-38108", "CVE-2025-38112", "CVE-2025-38115", "CVE-2025-38126", "CVE-2025-38147", "CVE-2025-38157", "CVE-2025-38161", "CVE-2025-38166", "CVE-2025-38177", "CVE-2025-38180", "CVE-2025-38181", "CVE-2025-38192", "CVE-2025-38193", "CVE-2025-38198", "CVE-2025-38200", "CVE-2025-38211", "CVE-2025-38212", "CVE-2025-38213", "CVE-2025-38222", "CVE-2025-38249", "CVE-2025-38250", "CVE-2025-38264", "CVE-2025-38312", "CVE-2025-38319", "CVE-2025-38323", "CVE-2025-38337", "CVE-2025-38350", "CVE-2025-38375", "CVE-2025-38391", "CVE-2025-38403", "CVE-2025-38415", "CVE-2025-38420", "CVE-2025-38468", "CVE-2025-38477", "CVE-2025-38494", "CVE-2025-38495");
  script_tag(name:"creation_date", value:"2025-08-20 04:10:46 +0000 (Wed, 20 Aug 2025)");
  script_version("2025-08-20T05:40:05+0000");
  script_tag(name:"last_modification", value:"2025-08-20 05:40:05 +0000 (Wed, 20 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-04-11 13:11:28 +0000 (Fri, 11 Apr 2025)");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:02846-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:02846-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-202502846-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1171844");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1205711");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1210629");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220631");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220704");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223634");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223638");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225000");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230216");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230581");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237881");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1238160");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1238374");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1238400");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240224");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240722");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1242365");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1242414");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1242446");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1242548");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1242780");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1242837");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1242960");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1243068");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1243479");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244735");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244750");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244792");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244801");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244840");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244860");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244883");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245051");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245058");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245060");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245073");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245078");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245121");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245132");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245139");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245151");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245201");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245210");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245217");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245265");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245649");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245668");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245675");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245682");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245689");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245708");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245747");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245758");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245768");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245777");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245945");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245952");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245954");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245970");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245976");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245986");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246000");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246008");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246029");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246037");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246045");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246171");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246182");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246243");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246253");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246386");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246387");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246459");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246473");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246781");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1247141");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1247147");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1247177");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1247181");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1247279");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1247314");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1247348");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1247349");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1247437");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-August/041247.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2025:02846-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP5 kernel was updated to receive various security bugfixes.


The following security bugs were fixed:

- CVE-2021-46984: Fixed an out of bounds access in kyber_bio_merge() in kyber (bsc#1220631).
- CVE-2021-46987: btrfs: fix deadlock when cloning inline extents and using qgroups (bsc#1220704).
- CVE-2022-4129: Fixed a denial of service with the Layer 2 Tunneling Protocol (L2TP). A missing lock when clearing sk_user_data can lead to a race condition and NULL pointer dereference (bsc#1205711).
- CVE-2022-49138: Bluetooth: hci_event: Fix checking conn for le_conn_complete_evt (bsc#1238160).
- CVE-2022-49319: iommu/arm-smmu-v3: check return value after calling platform_get_resource() (bsc#1238374).
- CVE-2022-49323: iommu/arm-smmu: fix possible null-ptr-deref in arm_smmu_device_probe() (bsc#1238400).
- CVE-2022-49768: 9p/fd: fix issue of list_del corruption in p9_fd_cancel() (bsc#1242446).
- CVE-2022-49825: ata: libata-transport: fix error handling in ata_tport_add() (bsc#1242548).
- CVE-2022-49934: wifi: mac80211: Fix UAF in ieee80211_scan_rx() (bsc#1245051).
- CVE-2022-49948: vt: Clear selection before changing the font (bsc#1245058).
- CVE-2022-49969: drm/amd/display: clear optc underflow before turn off odm clock (bsc#1245060).
- CVE-2022-49993: loop: Check for overflow while configuring loop (bsc#1245121).
- CVE-2022-50025: cxl: Fix a memory leak in an error handling path (bsc#1245132).
- CVE-2022-50027: scsi: lpfc: Fix possible memory leak when failing to issue CMF WQE (bsc#1245073).
- CVE-2022-50030: scsi: lpfc: Prevent buffer overflow crashes in debugfs with malformed user input (bsc#1245265).
- CVE-2022-50033: usb: host: ohci-ppc-of: Fix refcount leak bug (bsc#1245139).
- CVE-2022-50103: sched, cpuset: Fix dl_cpu_busy() panic due to empty cs->cpus_allowed (bsc#1244840).
- CVE-2022-50149: driver core: fix potential deadlock in __driver_attach (bsc#1244883).
- CVE-2022-50226: crypto: ccp - Use kzalloc for sev ioctl interfaces to prevent kernel memory leak (bsc#1244860).
- CVE-2023-2176: Fixed an out-of-boundary read in compare_netdev_and_ip in drivers/infiniband/core/cma.c in RDMA (bsc#1210629).
- CVE-2023-52878: can: dev: can_put_echo_skb(): do not crash kernel if can_priv::echo_skb is accessed out of bounds (bsc#1225000).
- CVE-2023-53020: l2tp: close all race conditions in l2tp_tunnel_register() (bsc#1240224).
- CVE-2023-53117: fs: prevent out-of-bounds array speculation when closing a file descriptor (bsc#1242780).
- CVE-2023-53118: scsi: core: Fix a procfs host directory removal regression (bsc#1242365).
- CVE-2024-26974: crypto: qat - resolve race condition during AER recovery (bsc#1223638).
- CVE-2024-26982: Fixed Squashfs inode number check not to be an invalid value of zero (bsc#1223634).
- CVE-2024-44963: btrfs: do not BUG_ON() when freeing tree block after error (bsc#1230216).
- CVE-2024-46713: kabi fix for perf/aux: Fix AUX ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 12-SP5.");

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

  if(!isnull(res = isrpmvuln(pkg:"cluster-md-kmp-default", rpm:"cluster-md-kmp-default~4.12.14~122.269.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dlm-kmp-default", rpm:"dlm-kmp-default~4.12.14~122.269.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gfs2-kmp-default", rpm:"gfs2-kmp-default~4.12.14~122.269.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.12.14~122.269.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.12.14~122.269.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.12.14~122.269.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~4.12.14~122.269.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.12.14~122.269.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.12.14~122.269.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.12.14~122.269.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.12.14~122.269.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-kmp-default", rpm:"ocfs2-kmp-default~4.12.14~122.269.1", rls:"SLES12.0SP5"))) {
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
