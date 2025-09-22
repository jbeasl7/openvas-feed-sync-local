# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2025.2012");
  script_cve_id("CVE-2022-49266", "CVE-2022-49557", "CVE-2022-49967", "CVE-2022-50230", "CVE-2022-50232", "CVE-2023-53068", "CVE-2023-53091", "CVE-2023-53093", "CVE-2024-57841", "CVE-2024-58098", "CVE-2025-21701", "CVE-2025-21817", "CVE-2025-22058", "CVE-2025-23142", "CVE-2025-23149", "CVE-2025-37738", "CVE-2025-37757", "CVE-2025-37788", "CVE-2025-37797", "CVE-2025-37798", "CVE-2025-37808", "CVE-2025-37823", "CVE-2025-37824", "CVE-2025-37839", "CVE-2025-37862", "CVE-2025-37867", "CVE-2025-37890", "CVE-2025-37911", "CVE-2025-37913", "CVE-2025-37915", "CVE-2025-37920", "CVE-2025-37923", "CVE-2025-37927", "CVE-2025-37930", "CVE-2025-37932", "CVE-2025-37940", "CVE-2025-37948", "CVE-2025-37963", "CVE-2025-37995", "CVE-2025-37997", "CVE-2025-38000", "CVE-2025-38001", "CVE-2025-38014", "CVE-2025-38044", "CVE-2025-38052", "CVE-2025-38061", "CVE-2025-38066", "CVE-2025-38068", "CVE-2025-38074", "CVE-2025-38075", "CVE-2025-38083", "CVE-2025-38084", "CVE-2025-38100", "CVE-2025-38102", "CVE-2025-38108", "CVE-2025-38112", "CVE-2025-38127", "CVE-2025-38129", "CVE-2025-38229", "CVE-2025-38285", "CVE-2025-38324", "CVE-2025-38337");
  script_tag(name:"creation_date", value:"2025-09-10 04:27:54 +0000 (Wed, 10 Sep 2025)");
  script_version("2025-09-10T05:38:24+0000");
  script_tag(name:"last_modification", value:"2025-09-10 05:38:24 +0000 (Wed, 10 Sep 2025)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-01-21 17:38:48 +0000 (Tue, 21 Jan 2025)");

  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2025-2012)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP12\-X86_64");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2025-2012");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2025-2012");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'kernel' package(s) announced via the EulerOS-SA-2025-2012 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"net_sched: hfsc: Fix a UAF vulnerability in class with netem as child qdisc(CVE-2025-37890)

crypto: lzo - Fix compression buffer overrun(CVE-2025-38068)

net: pktgen: fix access outside of user given buffer in pktgen_thread_write().(CVE-2025-38061)

net_sched: drr: Fix double list add in class with netem as child qdisc(CVE-2025-37915)

page_pool: Fix use-after-free in page_pool_recycle_in_ring(CVE-2025-38129)

net_sched: qfq: Fix double list add in class with netem as child qdisc(CVE-2025-37913)

net: avoid race between device unregistration and ethnl ops(CVE-2025-21701)

sctp: detect and prevent references to a freed transport in sendmsg(CVE-2025-23142)

codel: remove sch->q.qlen check before qdisc_tree_reduce_backlog().(CVE-2025-37798)

net: Fix TOCTOU issue in sk_is_readable().(CVE-2025-38112)

mpls: Use rcu_dereference_rtnl() in mpls_route_input_rcu().(CVE-2025-38324)

vhost-scsi: protect vq->log_used with vq->mutex(CVE-2025-38074)

ftrace: Add cond_resched() to ftrace_graph_set_hash().(CVE-2025-37940)

crypto: null - Use spin lock instead of mutex(CVE-2025-37808)

tipc: fix memory leak in tipc_link_xmit(CVE-2025-37757)

ice: fix Tx scheduler error handling in XDP callback(CVE-2025-38127)

dmaengine: idxd: Refactor remove call with idxd_cleanup() helper(CVE-2025-38014)

arm64: set UXN on swapper page tables(CVE-2022-50232)

tipc: fix NULL pointer dereference in tipc_mon_reinit_self().(CVE-2025-37824)

ext4: update s_journal_inum if it changes after journal replay(CVE-2023-53091)

media: cx231xx: set device_caps for 417(CVE-2025-38044)

net/tipc: fix slab-use-after-free Read in tipc_aead_encrypt_done(CVE-2025-38052)

RDMA/core: Silence oversized kvmalloc() warning(CVE-2025-37867)

tracing: Fix oob write in trace_seq_to_buffer().(CVE-2025-37923)

arm64: bpf: Add BHB mitigation to the epilogue for cBPF programs(CVE-2025-37948)

HID: pidff: Fix null pointer dereference in pidff_find_fields(CVE-2025-37862)

bpf: track changes_pkt_data property for global functions(CVE-2024-58098)

jbd2: remove wrong sb->s_sequence check(CVE-2025-37839)

udp: Fix memory accounting leak.(CVE-2025-22058)

tpm: do not start chip while suspended(CVE-2025-23149)

tracing: Do not let histogram values have some modifiers(CVE-2023-53093)

dm cache: prevent BUG_ON by blocking retries on failed device resumes(CVE-2025-38066)

netfilter: ipset: fix region locking in hash types(CVE-2025-37997)

bpf: Fix WARN() in get_bpf_raw_tp_regs(CVE-2025-38285)

block: fix rq-qos breakage from skipping rq_qos_done_bio().(CVE-2022-49266)

bnxt_en: Fix out-of-bound memcpy() during ethtool -w(CVE-2025-37911)

VMCI: fix race between vmci_host_setup_notify and vmci_ctx_unset_notify(CVE-2025-38102)

scsi: target: iscsi: Fix timeout on deleted connection(CVE-2025-38075)

iommu/amd: Fix potential buffer overflow in parse_ivrs_acpihid(CVE-2025-37927)

net: fix memory leak in tcp_conn_request().(CVE-2024-57841)

jbd2: fix ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel' package(s) on Huawei EulerOS V2.0SP12(x86_64).");

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

if(release == "EULEROS-2.0SP12-x86_64") {

  if(!isnull(res = isrpmvuln(pkg:"bpftool", rpm:"bpftool~5.10.0~136.12.0.86.h2674.eulerosv2r12", rls:"EULEROS-2.0SP12-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~5.10.0~136.12.0.86.h2674.eulerosv2r12", rls:"EULEROS-2.0SP12-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-abi-stablelists", rpm:"kernel-abi-stablelists~5.10.0~136.12.0.86.h2674.eulerosv2r12", rls:"EULEROS-2.0SP12-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~5.10.0~136.12.0.86.h2674.eulerosv2r12", rls:"EULEROS-2.0SP12-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~5.10.0~136.12.0.86.h2674.eulerosv2r12", rls:"EULEROS-2.0SP12-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-perf", rpm:"python3-perf~5.10.0~136.12.0.86.h2674.eulerosv2r12", rls:"EULEROS-2.0SP12-x86_64"))) {
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
