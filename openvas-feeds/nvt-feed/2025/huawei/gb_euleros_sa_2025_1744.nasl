# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2025.1744");
  script_cve_id("CVE-2022-48720", "CVE-2022-49052", "CVE-2022-49053", "CVE-2022-49058", "CVE-2022-49065", "CVE-2022-49076", "CVE-2022-49080", "CVE-2022-49114", "CVE-2022-49122", "CVE-2022-49156", "CVE-2022-49160", "CVE-2022-49171", "CVE-2022-49174", "CVE-2022-49206", "CVE-2022-49209", "CVE-2022-49210", "CVE-2022-49220", "CVE-2022-49236", "CVE-2022-49259", "CVE-2022-49271", "CVE-2022-49286", "CVE-2022-49287", "CVE-2022-49293", "CVE-2022-49295", "CVE-2022-49297", "CVE-2022-49300", "CVE-2022-49307", "CVE-2022-49308", "CVE-2022-49321", "CVE-2022-49341", "CVE-2022-49343", "CVE-2022-49344", "CVE-2022-49347", "CVE-2022-49348", "CVE-2022-49349", "CVE-2022-49352", "CVE-2022-49376", "CVE-2022-49377", "CVE-2022-49409", "CVE-2022-49411", "CVE-2022-49413", "CVE-2022-49414", "CVE-2022-49422", "CVE-2022-49434", "CVE-2022-49441", "CVE-2022-49446", "CVE-2022-49447", "CVE-2022-49450", "CVE-2022-49468", "CVE-2022-49472", "CVE-2022-49478", "CVE-2022-49497", "CVE-2022-49526", "CVE-2022-49535", "CVE-2022-49548", "CVE-2022-49549", "CVE-2022-49554", "CVE-2022-49563", "CVE-2022-49564", "CVE-2022-49566", "CVE-2022-49567", "CVE-2022-49589", "CVE-2022-49600", "CVE-2022-49601", "CVE-2022-49602", "CVE-2022-49603", "CVE-2022-49604", "CVE-2022-49620", "CVE-2022-49626", "CVE-2022-49627", "CVE-2022-49629", "CVE-2022-49631", "CVE-2022-49632", "CVE-2022-49637", "CVE-2022-49638", "CVE-2022-49639", "CVE-2022-49640", "CVE-2022-49641", "CVE-2022-49643", "CVE-2022-49648", "CVE-2022-49657", "CVE-2022-49658", "CVE-2022-49664", "CVE-2022-49667", "CVE-2022-49671", "CVE-2022-49673", "CVE-2022-49695", "CVE-2022-49696", "CVE-2022-49700", "CVE-2022-49707", "CVE-2022-49708", "CVE-2022-49715", "CVE-2022-49716", "CVE-2022-49720", "CVE-2023-52923", "CVE-2024-47141", "CVE-2024-47809", "CVE-2024-50290", "CVE-2024-53164", "CVE-2024-53168", "CVE-2024-53217", "CVE-2024-53680", "CVE-2024-56568", "CVE-2024-56636", "CVE-2024-56637", "CVE-2024-56644", "CVE-2024-56694", "CVE-2024-57795", "CVE-2024-57798", "CVE-2024-57890", "CVE-2024-57901", "CVE-2024-57902", "CVE-2024-57903", "CVE-2024-57931", "CVE-2024-57938", "CVE-2024-57947", "CVE-2025-21638", "CVE-2025-21639", "CVE-2025-21640", "CVE-2025-21648", "CVE-2025-21651", "CVE-2025-21653", "CVE-2025-21662", "CVE-2025-21665", "CVE-2025-21666", "CVE-2025-21667", "CVE-2025-21669", "CVE-2025-21682", "CVE-2025-21683", "CVE-2025-21687", "CVE-2025-21689", "CVE-2025-21690", "CVE-2025-21693", "CVE-2025-21694", "CVE-2025-21708", "CVE-2025-21726", "CVE-2025-21728", "CVE-2025-21731", "CVE-2025-21802", "CVE-2025-21814");
  script_tag(name:"creation_date", value:"2025-08-06 04:43:07 +0000 (Wed, 06 Aug 2025)");
  script_version("2025-08-08T05:44:56+0000");
  script_tag(name:"last_modification", value:"2025-08-08 05:44:56 +0000 (Fri, 08 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-02-21 16:49:03 +0000 (Fri, 21 Feb 2025)");

  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2025-1744)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT\-2\.13\.1");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2025-1744");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2025-1744");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'kernel' package(s) announced via the EulerOS-SA-2025-1744 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"ipv4: Fix a data-race around sysctl_fib_sync_mem.(CVE-2022-49637)

ima: Fix potential memory leak in ima_init_crypto().(CVE-2022-49627)

MIPS: pgalloc: fix memory leak caused by pgd_free().(CVE-2022-49210)

ip: Fix data-races around sysctl_ip_fwd_use_pmtu.(CVE-2022-49604)

net: tipc: fix possible refcount leak in tipc_sk_create()(CVE-2022-49620)

bpf, sockmap: Fix memleak in tcp_bpf_sendmsg while sk msg is full(CVE-2022-49209)

net: remove two BUG() from skb_checksum_help().(CVE-2022-49497)

usbnet: fix memory leak in error case(CVE-2022-49657)

ip: Fix a data-race around sysctl_ip_autobind_reuse.(CVE-2022-49600)

cipso: Fix data-races around sysctl.(CVE-2022-49639)

nexthop: Fix data-races around nexthop_compat_mode.(CVE-2022-49629)

tracing/histograms: Fix memory leak problem(CVE-2022-49648)

SUNRPC: Fix the svc_deferred_event trace class(CVE-2022-49065)

af_unix: Fix a data-race in unix_dgram_peer_wake_me().(CVE-2022-49344)

RDMA/cm: Fix memory leak in ib_cm_insert_listen(CVE-2022-49671)

ip: Fix a data-race around sysctl_fwmark_reflect.(CVE-2022-49602)

raw: Fix a data-race around sysctl_raw_l3mdev_accept.(CVE-2022-49631)

icmp: Fix data-races around sysctl.(CVE-2022-49638)

tty: synclink_gt: Fix null-pointer-dereference in slgt_clean().(CVE-2022-49307)

tipc: move bc link creation back to tipc_node_create(CVE-2022-49664)

icmp: Fix a data-race around sysctl_icmp_errors_use_inbound_ifaddr.(CVE-2022-49632)

xprtrdma: treat all calls not a bcall when bc_serv is NULL(CVE-2022-49321)

net: phy: micrel: Allow probing without .driver_data(CVE-2022-49472)

tcp/dccp: Fix a data-race around sysctl_tcp_fwmark_accept.(CVE-2022-49601)

ip: Fix data-races around sysctl_ip_fwd_update_priority.(CVE-2022-49603)

igb: fix a use-after-free issue in igb_clean_tx_ring(CVE-2022-49695)

rxrpc: Fix listen() setting the bar too high for the prealloc rings(CVE-2022-49450)

tty: fix deadlock caused by calling printk() under tty_port->lock(CVE-2022-49441)

media: pvrusb2: fix array-index-out-of-bounds in pvr2_i2c_core_init(CVE-2022-49478)

ima: Fix a potential integer overflow in ima_appraise_measurement(CVE-2022-49643)

scsi: qla2xxx: Fix scheduling while atomic(CVE-2022-49156)

mm/mempolicy: fix uninit-value in mpol_rebind_policy().(CVE-2022-49567)

dm raid: fix KASAN warning in raid5_add_disks(CVE-2022-49673)

padata: avoid UAF for reorder_work(CVE-2025-21726)

ARM: hisi: Add missing of_node_put after of_find_compatible_node(CVE-2022-49447)

ptp: Ensure info->enable callback is always set(CVE-2025-21814)

bpf: Send signals asynchronously if !preemptible(CVE-2025-21728)

ext4: don't BUG if someone dirty pages without asking ext4 first(CVE-2022-49171)

ext4: fix ext4_mb_mark_bb() with flex_bg with fast_commit(CVE-2022-49174)

dax: make sure inodes are flushed before destroy cache(CVE-2022-49220)

ext4: avoid cycles in directory h-tree(CVE-2022-49343)

ext4: fix bug_on in ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel' package(s) on Huawei EulerOS Virtualization release 2.13.1.");

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

if(release == "EULEROSVIRT-2.13.1") {

  if(!isnull(res = isrpmvuln(pkg:"bpftool", rpm:"bpftool~5.10.0~182.0.0.95.h2692.eulerosv2r13", rls:"EULEROSVIRT-2.13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~5.10.0~182.0.0.95.h2692.eulerosv2r13", rls:"EULEROSVIRT-2.13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-abi-stablelists", rpm:"kernel-abi-stablelists~5.10.0~182.0.0.95.h2692.eulerosv2r13", rls:"EULEROSVIRT-2.13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~5.10.0~182.0.0.95.h2692.eulerosv2r13", rls:"EULEROSVIRT-2.13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~5.10.0~182.0.0.95.h2692.eulerosv2r13", rls:"EULEROSVIRT-2.13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-perf", rpm:"python3-perf~5.10.0~182.0.0.95.h2692.eulerosv2r13", rls:"EULEROSVIRT-2.13.1"))) {
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
