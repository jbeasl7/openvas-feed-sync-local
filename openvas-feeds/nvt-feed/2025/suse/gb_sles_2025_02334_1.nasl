# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.02334.1");
  script_cve_id("CVE-2021-43527", "CVE-2021-47212", "CVE-2021-47455", "CVE-2021-47527", "CVE-2022-1679", "CVE-2022-21546", "CVE-2022-2586", "CVE-2022-3903", "CVE-2022-4095", "CVE-2022-4662", "CVE-2022-49154", "CVE-2022-49622", "CVE-2022-49731", "CVE-2022-49764", "CVE-2022-49780", "CVE-2022-49814", "CVE-2022-49879", "CVE-2022-49881", "CVE-2022-49917", "CVE-2022-49921", "CVE-2022-49936", "CVE-2022-49937", "CVE-2022-49938", "CVE-2022-49954", "CVE-2022-49956", "CVE-2022-49957", "CVE-2022-49977", "CVE-2022-49978", "CVE-2022-49986", "CVE-2022-49987", "CVE-2022-49990", "CVE-2022-50008", "CVE-2022-50012", "CVE-2022-50020", "CVE-2022-50022", "CVE-2022-50045", "CVE-2022-50055", "CVE-2022-50065", "CVE-2022-50067", "CVE-2022-50073", "CVE-2022-50083", "CVE-2022-50084", "CVE-2022-50085", "CVE-2022-50087", "CVE-2022-50091", "CVE-2022-50092", "CVE-2022-50093", "CVE-2022-50094", "CVE-2022-50097", "CVE-2022-50098", "CVE-2022-50099", "CVE-2022-50101", "CVE-2022-50102", "CVE-2022-50104", "CVE-2022-50109", "CVE-2022-50126", "CVE-2022-50134", "CVE-2022-50146", "CVE-2022-50152", "CVE-2022-50153", "CVE-2022-50173", "CVE-2022-50179", "CVE-2022-50181", "CVE-2022-50200", "CVE-2022-50206", "CVE-2022-50211", "CVE-2022-50213", "CVE-2022-50215", "CVE-2022-50220", "CVE-2023-1989", "CVE-2023-3111", "CVE-2023-52500", "CVE-2023-52927", "CVE-2023-53020", "CVE-2023-53063", "CVE-2023-53081", "CVE-2023-53090", "CVE-2023-53091", "CVE-2023-53133", "CVE-2023-53145", "CVE-2024-26586", "CVE-2024-26825", "CVE-2024-26872", "CVE-2024-26875", "CVE-2024-35790", "CVE-2024-35839", "CVE-2024-36959", "CVE-2024-38588", "CVE-2024-57982", "CVE-2025-21898", "CVE-2025-21920", "CVE-2025-21971", "CVE-2025-22035", "CVE-2025-23149", "CVE-2025-37756", "CVE-2025-37757", "CVE-2025-37781", "CVE-2025-37800", "CVE-2025-37810", "CVE-2025-37836", "CVE-2025-37844", "CVE-2025-37862", "CVE-2025-37892", "CVE-2025-37911", "CVE-2025-37923", "CVE-2025-37927", "CVE-2025-37928", "CVE-2025-37961", "CVE-2025-37980", "CVE-2025-37982", "CVE-2025-37992", "CVE-2025-37995", "CVE-2025-37998", "CVE-2025-38000", "CVE-2025-38004", "CVE-2025-38023", "CVE-2025-38024", "CVE-2025-38061", "CVE-2025-38072", "CVE-2025-38078", "CVE-2025-38083");
  script_tag(name:"creation_date", value:"2025-07-18 04:22:03 +0000 (Fri, 18 Jul 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-12-16 14:32:02 +0000 (Thu, 16 Dec 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:02334-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:02334-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-202502334-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1154048");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1190317");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1199487");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1201958");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1202095");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1202716");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1203254");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1205220");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1205514");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1206664");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1206878");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1206880");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1208542");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1210336");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1211226");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1212051");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218184");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220243");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220883");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222709");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223065");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223115");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223118");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224712");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224726");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225254");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225839");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226837");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1227768");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228659");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231293");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234454");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237312");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237913");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1238167");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1238275");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1238303");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1238570");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1239042");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1239071");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1239644");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1239986");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240224");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240610");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240686");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240785");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240799");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1241038");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1241544");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1242140");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1242154");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1242216");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1242243");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1242262");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1242281");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1242301");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1242359");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1242406");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1242423");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1242481");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1242498");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1242504");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1242515");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1242521");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1242575");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1242733");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1242753");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1242758");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1242767");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1242778");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1242849");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1242906");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1242946");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1242957");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1242982");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1243047");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1243469");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1243522");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1243523");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1243524");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1243536");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1243551");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1243620");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1243621");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1243698");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1243827");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1243836");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244241");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244274");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244277");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244317");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244337");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244737");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244743");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244783");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244786");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244788");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244802");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244813");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244820");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244836");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244838");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244839");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244841");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244842");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244845");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244848");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244849");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244851");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244867");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244884");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244885");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244886");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244901");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244936");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244948");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244966");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244967");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244968");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244969");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244976");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244978");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244984");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244986");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244992");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245004");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245009");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245024");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245025");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245039");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245047");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245057");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245117");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245119");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245125");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245129");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245131");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245138");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245140");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245147");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245149");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245152");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245183");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245195");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245348");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245440");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245455");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-July/040737.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2025:02334-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP5 kernel was updated to receive various security bugfixes.

The following security bugs were fixed:

- CVE-2021-47212: net/mlx5: Update error handler for UCTX and UMEM (bsc#1222709).
- CVE-2021-47455: ptp: Fix possible memory leak in ptp_clock_register() (bsc#1225254).
- CVE-2021-47527: serial: core: fix transmit-buffer reset and memleak (bsc#1227768).
- CVE-2022-21546: scsi: target: Fix WRITE_SAME No Data Buffer crash (bsc#1242243).
- CVE-2022-49154: KVM: SVM: fix panic on out-of-bounds guest IRQ (bsc#1238167).
- CVE-2022-49622: netfilter: nf_tables: fix crash when nf_trace is enabled (bsc#1239042).
- CVE-2022-49731: ata: libata-core: fix NULL pointer deref in ata_host_alloc_pinfo() (bsc#1239071).
- CVE-2022-49764: kABI: workaround 'bpf: Prevent bpf program recursion for raw tracepoint probes' changes (bsc#1242301).
- CVE-2022-49780: scsi: target: tcm_loop: Fix possible name leak in tcm_loop_setup_hba_bus() (bsc#1242262).
- CVE-2022-49814: kcm: close race conditions on sk_receive_queue (bsc#1242498).
- CVE-2022-49879: ext4: fix BUG_ON() when directory entry has invalid rec_len (bsc#1242733).
- CVE-2022-49881: wifi: cfg80211: fix memory leak in query_regdb_file() (bsc#1242481).
- CVE-2022-49917: ipvs: fix WARNING in ip_vs_app_net_cleanup() (bsc#1242406).
- CVE-2022-49921: net: sched: Fix use after free in red_enqueue() (bsc#1242359).
- CVE-2022-50055: iavf: Fix adminq error handling (bsc#1245039).
- CVE-2022-50087: firmware: arm_scpi: Ensure scpi_info is not assigned if the probe fails (bsc#1245119).
- CVE-2022-50134: RDMA/hfi1: fix potential memory leak in setup_base_ctxt() (bsc#1244802).
- CVE-2022-50200: selinux: Add boundary check in put_entry() (bsc#1245149).
- CVE-2023-52500: Fixed information leaking when processing OPC_INB_SET_CONTROLLER_CONFIG command (bsc#1220883).
- CVE-2023-52927: netfilter: allow exp not to be removed in nf_ct_find_expectation (bsc#1239644).
- CVE-2023-53020: l2tp: fix lockdep splat (bsc#1240224).
- CVE-2023-53090: drm/amdkfd: Fix an illegal memory access (bsc#1242753).
- CVE-2023-53091: ext4: update s_journal_inum if it changes after journal replay (bsc#1242767).
- CVE-2023-53133: bpf, sockmap: Fix an infinite loop error when len is 0 in tcp_bpf_recvmsg_parser() (bsc#1242423).
- CVE-2024-26586: mlxsw: spectrum_acl_tcam: Fix stack corruption (bsc#1220243).
- CVE-2024-26825: nfc: nci: free rx_data_reassembly skb on NCI device cleanup (bsc#1223065).
- CVE-2024-26872: RDMA/srpt: Do not register event handler until srpt device is fully setup (bsc#1223115).
- CVE-2024-26875: media: pvrusb2: fix uaf in pvr2_context_set_notify (bsc#1223118).
- CVE-2024-35790: usb: typec: altmodes/displayport: create sysfs nodes as driver's default device attribute group (bsc#1224712).
- CVE-2024-35839: kABI fix for netfilter: bridge: replace physindev with physinif in nf_bridge_info (bsc#1224726).
- CVE-2024-38588: ftrace: Fix ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 12-SP5.");

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

if(release == "SLES12.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"cluster-md-kmp-default", rpm:"cluster-md-kmp-default~4.12.14~122.266.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dlm-kmp-default", rpm:"dlm-kmp-default~4.12.14~122.266.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gfs2-kmp-default", rpm:"gfs2-kmp-default~4.12.14~122.266.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.12.14~122.266.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.12.14~122.266.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.12.14~122.266.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~4.12.14~122.266.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.12.14~122.266.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.12.14~122.266.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.12.14~122.266.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.12.14~122.266.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-kmp-default", rpm:"ocfs2-kmp-default~4.12.14~122.266.1", rls:"SLES12.0SP5"))) {
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
