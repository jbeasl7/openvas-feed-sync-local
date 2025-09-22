# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.1195.1");
  script_cve_id("CVE-2017-5753", "CVE-2021-4454", "CVE-2022-1016", "CVE-2022-49053", "CVE-2022-49293", "CVE-2022-49465", "CVE-2022-49650", "CVE-2022-49739", "CVE-2022-49746", "CVE-2022-49748", "CVE-2022-49751", "CVE-2022-49753", "CVE-2022-49755", "CVE-2022-49759", "CVE-2023-0179", "CVE-2023-1652", "CVE-2023-2162", "CVE-2023-3567", "CVE-2023-52930", "CVE-2023-52933", "CVE-2023-52935", "CVE-2023-52939", "CVE-2023-52941", "CVE-2023-52973", "CVE-2023-52974", "CVE-2023-52975", "CVE-2023-52976", "CVE-2023-52979", "CVE-2023-52983", "CVE-2023-52984", "CVE-2023-52988", "CVE-2023-52989", "CVE-2023-52992", "CVE-2023-52993", "CVE-2023-53000", "CVE-2023-53005", "CVE-2023-53006", "CVE-2023-53007", "CVE-2023-53008", "CVE-2023-53010", "CVE-2023-53015", "CVE-2023-53016", "CVE-2023-53019", "CVE-2023-53023", "CVE-2023-53024", "CVE-2023-53025", "CVE-2023-53026", "CVE-2023-53028", "CVE-2023-53029", "CVE-2023-53030", "CVE-2023-53033", "CVE-2024-50290", "CVE-2024-53063", "CVE-2024-53064", "CVE-2024-56651", "CVE-2024-58083", "CVE-2025-21693", "CVE-2025-21714", "CVE-2025-21732", "CVE-2025-21753", "CVE-2025-21772", "CVE-2025-21839");
  script_tag(name:"creation_date", value:"2025-04-14 04:07:33 +0000 (Mon, 14 Apr 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"4.7");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-01-06 19:33:57 +0000 (Mon, 06 Jan 2025)");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:1195-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:1195-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-20251195-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1193629");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1197227");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1207034");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1207186");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1207878");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1209262");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1209547");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1209788");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1210647");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1213167");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225742");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231375");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233479");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233557");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233558");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234464");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235528");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237029");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237530");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237875");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237877");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237890");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237918");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1238911");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1238919");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1239016");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1239036");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1239061");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1239126");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1239452");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1239454");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1239968");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1239969");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240133");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240195");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240205");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240207");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240208");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240210");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240212");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240213");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240218");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240220");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240227");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240229");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240231");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240242");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240245");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240247");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240250");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240254");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240256");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240264");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240266");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240272");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240275");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240276");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240278");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240279");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240280");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240281");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240282");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240283");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240284");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240286");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240288");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240290");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240292");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240293");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240297");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240304");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240308");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240309");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240317");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240318");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240322");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-April/038960.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2025:1195-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP4 kernel was updated to receive various security bugfixes.

The following security bugs were fixed:

- CVE-2022-49053: scsi: target: tcmu: Fix possible page UAF (bsc#1237918).
- CVE-2022-49465: blk-throttle: Set BIO_THROTTLED when bio has been throttled (bsc#1238919).
- CVE-2022-49739: gfs2: Always check inode size of inline inodes (bsc#1240207).
- CVE-2023-52935: mm/khugepaged: fix ->anon_vma race (bsc#1240276).
- CVE-2024-53064: idpf: fix idpf_vc_core_init error path (bsc#1233558 bsc#1234464).
- CVE-2024-56651: can: hi311x: hi3110_can_ist(): fix potential use-after-free (bsc#1235528).
- CVE-2024-58083: KVM: Explicitly verify target vCPU is online in kvm_get_vcpu() (bsc#1239036).
- CVE-2025-21693: mm: zswap: properly synchronize freeing resources during CPU hotunplug (bsc#1237029).
- CVE-2025-21714: RDMA/mlx5: Fix implicit ODP use after free (bsc#1237890).
- CVE-2025-21732: RDMA/mlx5: Fix a race for an ODP MR which leads to CQE with error (bsc#1237877).
- CVE-2025-21753: btrfs: fix use-after-free when attempting to join an aborted transaction (bsc#1237875).
- CVE-2025-21772: partitions: mac: fix handling of bogus partition table (bsc#1238911).

The following non-security bugs were fixed:

- ACPI: processor: idle: Return an error if both P_LVL{2,3} idle states are invalid (bsc#1237530).
- RDMA/mana_ib: Prefer struct_size over open coded arithmetic (bsc#1239016).
- RDMA/mana_ib: Use v2 version of cfg_rx_steer_req to enable RX coalescing (bsc#1239016).
- RDMA/mlx5: Fix implicit ODP hang on parent deregistration (git-fixes)
- btrfs: defrag: do not use merged extent map for their generation check (bsc#1239968).
- btrfs: fix defrag not merging contiguous extents due to merged extent maps (bsc#1239968).
- btrfs: fix extent map merging not happening for adjacent extents (bsc#1239968).
- btrfs: send: allow cloning non-aligned extent if it ends at i_size (bsc#1239969).
- btrfs: send: fix invalid clone operation for file that got its size decreased (bsc#1239969).
- gfs2: Fix inode height consistency check (git-fixes).
- mm/mmu_notifier.c: fix race in mmu_interval_notifier_remove() (bsc#1239126).
- mm: zswap: move allocations during CPU init outside the lock (git-fixes).
- net: mana: Add flex array to struct mana_cfg_rx_steer_req_v2 (bsc#1239016).
- net: mana: Allow variable size indirection table (bsc#1239016).
- net: mana: Avoid open coded arithmetic (bsc#1239016).
- net: mana: Fix error handling in mana_create_txq/rxq's NAPI cleanup (bsc#1240195).
- net: mana: Support holes in device list reply msg (bsc#1240133).");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 15-SP4, SUSE Linux Enterprise Server for SAP Applications 15-SP4.");

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

if(release == "SLES15.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb", rpm:"kernel-64kb~5.14.21~150400.24.161.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb-devel", rpm:"kernel-64kb-devel~5.14.21~150400.24.161.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~5.14.21~150400.24.161.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~5.14.21~150400.24.161.1.150400.24.80.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~5.14.21~150400.24.161.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~5.14.21~150400.24.161.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs", rpm:"kernel-docs~5.14.21~150400.24.161.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~5.14.21~150400.24.161.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build", rpm:"kernel-obs-build~5.14.21~150400.24.161.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~5.14.21~150400.24.161.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~5.14.21~150400.24.161.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-zfcpdump", rpm:"kernel-zfcpdump~5.14.21~150400.24.161.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default", rpm:"reiserfs-kmp-default~5.14.21~150400.24.161.1", rls:"SLES15.0SP4"))) {
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
