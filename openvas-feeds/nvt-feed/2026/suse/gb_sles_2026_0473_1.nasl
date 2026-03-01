# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2026.0473.1");
  script_cve_id("CVE-2022-48838", "CVE-2022-49943", "CVE-2022-49980", "CVE-2022-50347", "CVE-2022-50580", "CVE-2022-50676", "CVE-2022-50697", "CVE-2022-50709", "CVE-2022-50716", "CVE-2022-50717", "CVE-2022-50719", "CVE-2022-50740", "CVE-2022-50744", "CVE-2022-50749", "CVE-2022-50751", "CVE-2022-50760", "CVE-2022-50770", "CVE-2022-50777", "CVE-2022-50780", "CVE-2022-50782", "CVE-2022-50786", "CVE-2022-50816", "CVE-2022-50834", "CVE-2022-50865", "CVE-2022-50868", "CVE-2022-50880", "CVE-2022-50881", "CVE-2022-50884", "CVE-2022-50885", "CVE-2022-50887", "CVE-2023-50756", "CVE-2023-52525", "CVE-2023-52999", "CVE-2023-53148", "CVE-2023-53178", "CVE-2023-53226", "CVE-2023-53464", "CVE-2023-53685", "CVE-2023-53747", "CVE-2023-53751", "CVE-2023-53825", "CVE-2023-53853", "CVE-2023-53863", "CVE-2023-53992", "CVE-2023-54012", "CVE-2023-54047", "CVE-2023-54048", "CVE-2023-54067", "CVE-2023-54111", "CVE-2023-54112", "CVE-2023-54118", "CVE-2023-54121", "CVE-2023-54134", "CVE-2023-54198", "CVE-2023-54202", "CVE-2023-54207", "CVE-2023-54218", "CVE-2023-54230", "CVE-2023-54243", "CVE-2023-54265", "CVE-2023-54274", "CVE-2023-54282", "CVE-2023-54287", "CVE-2023-54311", "CVE-2023-54321", "CVE-2024-26832", "CVE-2024-26935", "CVE-2024-36903", "CVE-2024-41007", "CVE-2024-50040", "CVE-2024-56690", "CVE-2024-58020", "CVE-2025-21681", "CVE-2025-37913", "CVE-2025-38007", "CVE-2025-38539", "CVE-2025-38591", "CVE-2025-38602", "CVE-2025-38656", "CVE-2025-39689", "CVE-2025-39813", "CVE-2025-39829", "CVE-2025-39913", "CVE-2025-40087", "CVE-2025-40088", "CVE-2025-40115", "CVE-2025-40198", "CVE-2025-40259", "CVE-2025-40261", "CVE-2025-40264", "CVE-2025-40271", "CVE-2025-40323", "CVE-2025-40339", "CVE-2025-40345", "CVE-2025-40363", "CVE-2025-68188", "CVE-2025-68190", "CVE-2025-68192", "CVE-2025-68241", "CVE-2025-68245", "CVE-2025-68261", "CVE-2025-68264", "CVE-2025-68286", "CVE-2025-68296", "CVE-2025-68303", "CVE-2025-68305", "CVE-2025-68312", "CVE-2025-68337", "CVE-2025-68349", "CVE-2025-68354", "CVE-2025-68362", "CVE-2025-68366", "CVE-2025-68367", "CVE-2025-68372", "CVE-2025-68379", "CVE-2025-68740", "CVE-2025-68757", "CVE-2025-68767", "CVE-2025-68771", "CVE-2025-68774", "CVE-2025-68783", "CVE-2025-68788", "CVE-2025-68795", "CVE-2025-68797", "CVE-2025-68813", "CVE-2025-68816", "CVE-2025-71064", "CVE-2025-71082", "CVE-2025-71085", "CVE-2025-71087", "CVE-2025-71091", "CVE-2025-71093", "CVE-2025-71096", "CVE-2025-71098", "CVE-2025-71108", "CVE-2025-71112", "CVE-2025-71119", "CVE-2025-71120", "CVE-2025-71123", "CVE-2026-22976", "CVE-2026-22978", "CVE-2026-22988", "CVE-2026-22999", "CVE-2026-23001", "CVE-2026-23011");
  script_tag(name:"creation_date", value:"2026-02-16 04:44:21 +0000 (Mon, 16 Feb 2026)");
  script_version("2026-02-16T06:02:08+0000");
  script_tag(name:"last_modification", value:"2026-02-16 06:02:08 +0000 (Mon, 16 Feb 2026)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-01-16 19:48:30 +0000 (Fri, 16 Jan 2026)");

  script_name("SUSE: Security Advisory (SUSE-SU-2026:0473-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:0473-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-20260473-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1205462");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1214285");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220840");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223007");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223675");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225527");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225741");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1227863");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1227988");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231908");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235428");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1236702");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1239346");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240299");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1243471");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244904");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244938");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245110");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248211");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248341");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248363");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248643");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249307");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249658");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249827");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249842");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249854");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249928");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250032");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250082");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250705");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250759");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250868");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251770");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252542");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252909");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253318");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253453");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253739");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254244");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254572");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254657");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254673");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254689");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254707");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254835");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254839");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254845");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254986");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255094");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255102");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255122");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255128");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255131");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255157");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255164");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255169");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255171");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255246");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255268");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255269");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255279");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255297");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255351");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255380");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255428");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255482");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255537");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255544");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255547");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255553");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255565");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255571");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255594");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255611");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255622");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255695");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255762");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255773");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255804");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255810");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255812");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255839");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255844");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255874");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255880");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255905");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255908");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255925");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255939");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255943");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255961");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255970");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255983");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256038");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256058");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256106");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256122");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256125");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256127");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256130");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256131");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256132");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256149");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256155");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256165");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256168");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256184");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256191");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256216");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256219");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256221");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256229");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256258");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256267");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256282");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256305");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256320");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256354");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256369");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256386");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256395");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256398");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256580");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256582");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256585");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256591");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256606");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256611");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256623");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256628");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256638");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256641");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256650");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256654");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256660");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256674");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256688");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256726");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256730");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256757");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256773");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256774");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256777");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256779");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256792");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257035");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257207");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257227");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257229");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257232");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257236");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257282");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2026-February/024136.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2026:0473-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP5 kernel was updated to fix various security issues

The following security issues were fixed:

- CVE-2022-50347: mmc: rtsx_usb_sdmmc: fix return value check of mmc_add_host() (bsc#1249928).
- CVE-2022-50580: blk-throttle: prevent overflow while calculating wait time (bsc#1252542).
- CVE-2022-50676: net: rds: don't hold sock lock when cancelling work from rds_tcp_reset_callbacks() (bsc#1254689).
- CVE-2022-50697: mrp: introduce active flags to prevent UAF when applicant uninit (bsc#1255594).
- CVE-2022-50709: wifi: ath9k: avoid uninit memory read in ath9k_htc_rx_msg() (bsc#1255565).
- CVE-2022-50716: wifi: ar5523: Fix use-after-free on ar5523_cmd() timed out (bsc#1255839).
- CVE-2022-50717: nvmet-tcp: add bounds check on Transfer Tag (bsc#1255844).
- CVE-2022-50719: ALSA: line6: fix stack overflow in line6_midi_transmit (bsc#1255939).
- CVE-2022-50740: wifi: ath9k: hif_usb: fix memory leak of urbs in ath9k_hif_usb_dealloc_tx_urbs() (bsc#1256155).
- CVE-2022-50744: scsi: lpfc: Fix hard lockup when reading the rx_monitor from debugfs (bsc#1256165).
- CVE-2022-50749: acct: fix potential integer overflow in encode_comp_t() (bsc#1256191).
- CVE-2022-50751: configfs: fix possible memory leak in configfs_create_dir() (bsc#1256184).
- CVE-2022-50760: drm/amdgpu: Fix PCI device refcount leak in amdgpu_atrm_get_bios() (bsc#1255983).
- CVE-2022-50770: ocfs2: fix memory leak in ocfs2_mount_volume() (bsc#1256221).
- CVE-2022-50777: net: phy: xgmiitorgmii: Fix refcount leak in xgmiitorgmii_probe (bsc#1256320).
- CVE-2022-50780: net: fix UAF issue in nfqnl_nf_hook_drop() when ops_init() failed (bsc#1256305).
- CVE-2022-50782: ext4: fix bug_on in __es_tree_search caused by bad quota inode (bsc#1256282).
- CVE-2022-50786: media: s5p-mfc: Clear workbit to handle error condition (bsc#1256258).
- CVE-2022-50816: ipv6: ensure sane device mtu in tunnels (bsc#1256038).
- CVE-2022-50834: nfc: Fix potential resource leaks (bsc#1256219).
- CVE-2022-50865: tcp: fix a signed-integer-overflow bug in tcp_add_backlog() (bsc#1256168).
- CVE-2022-50868: hwrng: amd - Fix PCI device refcount leak (bsc#1256386).
- CVE-2022-50880: wifi: ath10k: add peer map clean up for peer delete in ath10k_sta_state() (bsc#1256132).
- CVE-2022-50881: ath9k: Fix typo in function name (bsc#1256130).
- CVE-2022-50884: drm: Prevent drm_copy_field() to attempt copying a NULL pointer (bsc#1256127).
- CVE-2022-50885: RDMA/rxe: Fix NULL-ptr-deref in rxe_qp_do_cleanup() when socket create failed (bsc#1256122).
- CVE-2022-50887: regulator: core: fix unbalanced of node refcount in regulator_dev_lookup() (bsc#1256125).
- CVE-2023-50756: nvme-pci: fix mempool alloc size (bsc#1256216).
- CVE-2023-53685: tun: Fix memory leak for detached NAPI queue (bsc#1251770).
- CVE-2023-53747: vc_screen: reload load of struct vc_data pointer in vcs_write() to avoid UAF (bsc#1254572).
- CVE-2023-53751: cifs: fix ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"cluster-md-kmp-default", rpm:"cluster-md-kmp-default~4.12.14~122.293.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dlm-kmp-default", rpm:"dlm-kmp-default~4.12.14~122.293.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gfs2-kmp-default", rpm:"gfs2-kmp-default~4.12.14~122.293.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.12.14~122.293.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.12.14~122.293.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.12.14~122.293.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~4.12.14~122.293.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.12.14~122.293.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.12.14~122.293.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.12.14~122.293.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.12.14~122.293.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-kmp-default", rpm:"ocfs2-kmp-default~4.12.14~122.293.1", rls:"SLES12.0SP5"))) {
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
