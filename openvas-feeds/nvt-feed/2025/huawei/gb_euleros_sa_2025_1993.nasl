# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2025.1993");
  script_cve_id("CVE-2021-33061", "CVE-2022-49267", "CVE-2022-49357", "CVE-2022-49420", "CVE-2022-49474", "CVE-2022-49571", "CVE-2022-49572", "CVE-2022-49573", "CVE-2022-49575", "CVE-2022-49583", "CVE-2022-49586", "CVE-2022-49587", "CVE-2022-49727", "CVE-2022-49779", "CVE-2022-49780", "CVE-2022-49788", "CVE-2022-49799", "CVE-2022-49802", "CVE-2022-49823", "CVE-2022-49825", "CVE-2022-49826", "CVE-2022-49827", "CVE-2022-49832", "CVE-2022-49837", "CVE-2022-49839", "CVE-2022-49840", "CVE-2022-49846", "CVE-2022-49853", "CVE-2022-49862", "CVE-2022-49869", "CVE-2022-49871", "CVE-2022-49873", "CVE-2022-49874", "CVE-2022-49875", "CVE-2022-49878", "CVE-2022-49879", "CVE-2022-49880", "CVE-2022-49885", "CVE-2022-49889", "CVE-2022-49890", "CVE-2022-49892", "CVE-2022-49899", "CVE-2022-49900", "CVE-2022-49901", "CVE-2022-49921", "CVE-2022-49925", "CVE-2022-49927", "CVE-2023-52977", "CVE-2023-52983", "CVE-2023-53060", "CVE-2023-53075", "CVE-2023-53089", "CVE-2023-53091", "CVE-2023-53093", "CVE-2023-53100", "CVE-2023-53101", "CVE-2023-53116", "CVE-2023-53118", "CVE-2023-53124", "CVE-2023-53134", "CVE-2023-53137", "CVE-2023-53143", "CVE-2024-50019", "CVE-2024-57841", "CVE-2024-57951", "CVE-2024-57982", "CVE-2024-58098", "CVE-2025-21703", "CVE-2025-22026", "CVE-2025-22027", "CVE-2025-22058", "CVE-2025-22063", "CVE-2025-22090", "CVE-2025-22113", "CVE-2025-22121", "CVE-2025-23131", "CVE-2025-23136", "CVE-2025-23150", "CVE-2025-37738", "CVE-2025-37752", "CVE-2025-37785", "CVE-2025-37807", "CVE-2025-37839", "CVE-2025-37867", "CVE-2025-37940", "CVE-2025-39728");
  script_tag(name:"creation_date", value:"2025-08-12 04:32:34 +0000 (Tue, 12 Aug 2025)");
  script_version("2025-08-13T05:40:47+0000");
  script_tag(name:"last_modification", value:"2025-08-13 05:40:47 +0000 (Wed, 13 Aug 2025)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-02-14 15:57:18 +0000 (Fri, 14 Feb 2025)");

  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2025-1993)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP13");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2025-1993");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2025-1993");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'kernel' package(s) announced via the EulerOS-SA-2025-1993 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"RDMA/core: Silence oversized kvmalloc() warning(CVE-2025-37867)

igb: revert rtnl_lock() that causes deadlock(CVE-2023-53060)

bnxt_en: Avoid order-5 memory allocation for TPA data(CVE-2023-53134)

net_sched: sch_sfq: move the limit validation(CVE-2025-37752)

ftrace: Add cond_resched() to ftrace_graph_set_hash().(CVE-2025-37940)

net: annotate races around sk->sk_bound_dev_if(CVE-2022-49420)

ext4: fix off-by-one error in do_split(CVE-2025-23150)

jbd2: remove wrong sb->s_sequence check(CVE-2025-37839)

ext4: update s_journal_inum if it changes after journal replay(CVE-2023-53091)

udp: Fix memory accounting leak.(CVE-2025-22058)

netem: Update sch->q.qlen before qdisc_tree_reduce_backlog().(CVE-2025-21703)

net: fix memory leak in tcp_conn_request().(CVE-2024-57841)

xfrm: state: fix out-of-bounds read during lookup(CVE-2024-57982)

Insufficient control flow management for the Intel(R) 82599 Ethernet Controllers and Adapters may allow an authenticated user to potentially enable denial of service via local access.(CVE-2021-33061)

udf: Fix a slab-out-of-bounds write bug in udf_find_entry().(CVE-2022-49846)

nvmet: avoid potential UAF in nvmet_req_complete().(CVE-2023-53116)

ata: libata-transport: fix error handling in ata_tport_add().(CVE-2022-49825)

ata: libata-transport: fix double ata_host_put() in ata_tport_add().(CVE-2022-49826)

bpf: track changes_pkt_data property for global functions(CVE-2024-58098)

pinctrl: devicetree: fix null pointer dereferencing in pinctrl_dt_to_map(CVE-2022-49832)

scsi: core: Fix a procfs host directory removal regression(CVE-2023-53118)

bpf, verifier: Fix memory leak in array reallocation for stack state(CVE-2022-49878)

kprobes: Skip clearing aggrprobe's post_handler in kprobe-on-ftrace case(CVE-2022-49779)

i2c: piix4: Fix adapter not be removed in piix4_remove().(CVE-2022-49900)

bpf: Fix kmemleak warning for percpu hashmap(CVE-2025-37807)

drm: Fix potential null-ptr-deref in drm_vblank_destroy_worker().(CVE-2022-49827)

RDMA/core: Fix null-ptr-deref in ib_core_cleanup().(CVE-2022-49925)

net: tun: Fix memory leaks of napi_get_frags(CVE-2022-49871)

net: sched: Fix use after free in red_enqueue().(CVE-2022-49921)

bnxt_en: Fix possible crash in bnxt_hwrm_set_coal().(CVE-2022-49869)

tipc: fix the msg->req tlv len check in tipc_nl_compat_name_table_dump_header(CVE-2022-49862)

bpf, test_run: Fix alignment problem in bpf_prog_test_run_skb().(CVE-2022-49840)

net: macvlan: fix memory leaks of macvlan_common_newlink(CVE-2022-49853)

HID: hyperv: fix possible memory leak in mousevsc_probe().(CVE-2022-49874)

bpftool: Fix NULL pointer dereference when pin {PROG, MAP, LINK} without FILE(CVE-2022-49875)

ftrace: Fix null pointer dereference in ftrace_add_mod().(CVE-2022-49802)

tracing: Do not let histogram values have some modifiers(CVE-2023-53093)

ftrace: Fix invalid address access in lookup_rec() when index is ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel' package(s) on Huawei EulerOS V2.0SP13.");

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

if(release == "EULEROS-2.0SP13") {

  if(!isnull(res = isrpmvuln(pkg:"bpftool", rpm:"bpftool~5.10.0~182.0.0.95.h2826.eulerosv2r13", rls:"EULEROS-2.0SP13"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~5.10.0~182.0.0.95.h2826.eulerosv2r13", rls:"EULEROS-2.0SP13"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-abi-stablelists", rpm:"kernel-abi-stablelists~5.10.0~182.0.0.95.h2826.eulerosv2r13", rls:"EULEROS-2.0SP13"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~5.10.0~182.0.0.95.h2826.eulerosv2r13", rls:"EULEROS-2.0SP13"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~5.10.0~182.0.0.95.h2826.eulerosv2r13", rls:"EULEROS-2.0SP13"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-perf", rpm:"python3-perf~5.10.0~182.0.0.95.h2826.eulerosv2r13", rls:"EULEROS-2.0SP13"))) {
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
