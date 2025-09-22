# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.01600.1");
  script_cve_id("CVE-2020-36789", "CVE-2021-47659", "CVE-2021-47668", "CVE-2021-47669", "CVE-2022-49044", "CVE-2022-49055", "CVE-2022-49060", "CVE-2022-49086", "CVE-2022-49111", "CVE-2022-49118", "CVE-2022-49121", "CVE-2022-49137", "CVE-2022-49171", "CVE-2022-49175", "CVE-2022-49176", "CVE-2022-49179", "CVE-2022-49188", "CVE-2022-49197", "CVE-2022-49205", "CVE-2022-49232", "CVE-2022-49290", "CVE-2022-49305", "CVE-2022-49325", "CVE-2022-49335", "CVE-2022-49351", "CVE-2022-49385", "CVE-2022-49390", "CVE-2022-49411", "CVE-2022-49442", "CVE-2022-49465", "CVE-2022-49478", "CVE-2022-49489", "CVE-2022-49504", "CVE-2022-49521", "CVE-2022-49525", "CVE-2022-49534", "CVE-2022-49535", "CVE-2022-49536", "CVE-2022-49537", "CVE-2022-49542", "CVE-2022-49561", "CVE-2022-49590", "CVE-2022-49658", "CVE-2022-49668", "CVE-2022-49693", "CVE-2022-49725", "CVE-2022-49728", "CVE-2022-49730", "CVE-2022-49749", "CVE-2022-49753", "CVE-2023-53023", "CVE-2023-53032", "CVE-2024-46763", "CVE-2024-46865", "CVE-2024-49994", "CVE-2024-50038", "CVE-2024-50272", "CVE-2024-52559", "CVE-2024-54683", "CVE-2024-56590", "CVE-2024-56641", "CVE-2024-57924", "CVE-2024-57980", "CVE-2024-57981", "CVE-2024-58005", "CVE-2024-58009", "CVE-2024-58017", "CVE-2024-58063", "CVE-2024-58093", "CVE-2025-21635", "CVE-2025-21735", "CVE-2025-21750", "CVE-2025-21758", "CVE-2025-21764", "CVE-2025-21768", "CVE-2025-21772", "CVE-2025-21779", "CVE-2025-21806", "CVE-2025-21862", "CVE-2025-21881", "CVE-2025-21909", "CVE-2025-21910", "CVE-2025-21926", "CVE-2025-21927", "CVE-2025-21931", "CVE-2025-21941", "CVE-2025-21948", "CVE-2025-21956", "CVE-2025-21957", "CVE-2025-21963", "CVE-2025-21964", "CVE-2025-21976", "CVE-2025-22004", "CVE-2025-22008", "CVE-2025-22010", "CVE-2025-22018", "CVE-2025-22053", "CVE-2025-22055", "CVE-2025-22060", "CVE-2025-22086", "CVE-2025-23131", "CVE-2025-37785");
  script_tag(name:"creation_date", value:"2025-05-22 12:07:17 +0000 (Thu, 22 May 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-04-11 13:11:42 +0000 (Fri, 11 Apr 2025)");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:01600-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:01600-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-202501600-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1205495");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230764");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231103");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231450");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231910");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233461");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234209");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235038");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235526");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235729");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235870");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1236086");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1236111");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237757");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237839");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237840");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237845");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237868");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237873");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237885");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237911");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237912");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237926");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237939");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237950");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237951");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237954");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237957");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237979");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237984");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1238000");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1238016");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1238022");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1238037");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1238092");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1238093");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1238097");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1238099");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1238138");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1238139");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1238155");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1238156");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1238233");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1238243");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1238244");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1238307");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1238335");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1238377");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1238398");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1238455");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1238497");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1238507");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1238537");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1238645");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1238714");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1238722");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1238737");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1238746");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1238760");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1238768");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1238803");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1238835");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1238838");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1238844");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1238893");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1238905");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1238911");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1238919");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1238930");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1238937");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1238938");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1238984");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1239070");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1239111");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1239112");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1239474");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1239994");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240185");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240243");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240250");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240270");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240309");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240583");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240590");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240701");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240703");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240709");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240712");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240714");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240717");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240739");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240740");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240742");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240835");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240942");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240943");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1241145");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1241266");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1241347");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1241371");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1241373");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1241404");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1241405");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1241408");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1241458");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1241526");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1241601");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1241640");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1242778");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-May/039257.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2025:01600-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP5 kernel was updated to receive various security bugfixes.


The following security bugs were fixed:

- CVE-2021-47659: drm/plane: Move range check for format_count earlier (bsc#1237839).
- CVE-2022-49044: dm integrity: fix memory corruption when tag_size is less than digest size (bsc#1237840).
- CVE-2022-49055: drm/amdkfd: Check for potential null return of kmalloc_array() (bsc#1237868).
- CVE-2022-49060: net/smc: Fix NULL pointer dereference in smc_pnet_find_ib() (bsc#1237845).
- CVE-2022-49086: net: openvswitch: fix leak of nested actions (bsc#1238037).
- CVE-2022-49111: Bluetooth: Fix use after free in hci_send_acl (bsc#1237984).
- CVE-2022-49118: scsi: hisi_sas: Free irq vectors in order for v3 HW (bsc#1237979).
- CVE-2022-49121: scsi: pm8001: Fix tag leaks on error (bsc#1237926).
- CVE-2022-49137: drm/amd/amdgpu/amdgpu_cs: fix refcount leak of a dma_fence obj (bsc#1238155).
- CVE-2022-49175: PM: core: keep irq flags in device_pm_check_callbacks() (bsc#1238099).
- CVE-2022-49176: bfq: fix use-after-free in bfq_dispatch_request (bsc#1238097).
- CVE-2022-49179: block, bfq: do not move oom_bfqq (bsc#1238092).
- CVE-2022-49188: remoteproc: qcom_q6v5_mss: Fix some leaks in q6v5_alloc_memory_region (bsc#1238138).
- CVE-2022-49197: af_netlink: Fix shift out of bounds in group mask calculation (bsc#1238455).
- CVE-2022-49205: bpf, sockmap: Fix double uncharge the mem of sk_msg (bsc#1238335).
- CVE-2022-49232: drm/amd/display: Fix a NULL pointer dereference in amdgpu_dm_connector_add_common_modes() (bsc#1238139).
- CVE-2022-49290: mac80211: fix potential double free on mesh join (bsc#1238156).
- CVE-2022-49305: drivers: staging: rtl8192u: Fix deadlock in ieee80211_beacons_stop() (bsc#1238645).
- CVE-2022-49325: tcp: add accessors to read/set tp->snd_cwnd (bsc#1238398).
- CVE-2022-49335: drm/amdgpu/cs: make commands with 0 chunks illegal behaviour (bsc#1238377).
- CVE-2022-49351: net: altera: Fix refcount leak in altera_tse_mdio_create (bsc#1237939).
- CVE-2022-49385: driver: base: fix UAF when driver_attach failed (bsc#1237951).
- CVE-2022-49390: macsec: fix UAF bug for real_dev (bsc#1238233).
- CVE-2022-49411: bfq: Make sure bfqg for which we are queueing requests is online (bsc#1238307).
- CVE-2022-49442: drivers/base/node.c: fix compaction sysfs file leak (bsc#1238243).
- CVE-2022-49465: blk-throttle: Set BIO_THROTTLED when bio has been throttled (bsc#1238919).
- CVE-2022-49478: media: pvrusb2: fix array-index-out-of-bounds in pvr2_i2c_core_init (bsc#1238000).
- CVE-2022-49489: drm/msm/disp/dpu1: set vbif hw config to NULL to avoid use after memory free during pm runtime resume (bsc#1238244).
- CVE-2022-49504: scsi: lpfc: Inhibit aborts if external loopback plug is inserted (bsc#1238835).
- CVE-2022-49521: scsi: lpfc: Fix resource leak in lpfc_sli4_send_seq_to_ulp() (bsc#1238938).
- CVE-2022-49525: media: cx25821: Fix the warning when ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"cluster-md-kmp-default", rpm:"cluster-md-kmp-default~4.12.14~122.258.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dlm-kmp-default", rpm:"dlm-kmp-default~4.12.14~122.258.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gfs2-kmp-default", rpm:"gfs2-kmp-default~4.12.14~122.258.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.12.14~122.258.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.12.14~122.258.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.12.14~122.258.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~4.12.14~122.258.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.12.14~122.258.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.12.14~122.258.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.12.14~122.258.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.12.14~122.258.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-kmp-default", rpm:"ocfs2-kmp-default~4.12.14~122.258.1", rls:"SLES12.0SP5"))) {
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
