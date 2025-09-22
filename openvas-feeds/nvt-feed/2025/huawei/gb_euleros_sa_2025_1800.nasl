# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2025.1800");
  script_cve_id("CVE-2022-49086", "CVE-2022-49350", "CVE-2022-49374", "CVE-2022-49429", "CVE-2022-49571", "CVE-2022-49572", "CVE-2022-49573", "CVE-2022-49574", "CVE-2022-49586", "CVE-2022-49587", "CVE-2022-49589", "CVE-2022-49590", "CVE-2022-49593", "CVE-2022-49595", "CVE-2022-49598", "CVE-2022-49601", "CVE-2022-49602", "CVE-2022-49604", "CVE-2022-49638", "CVE-2022-49657", "CVE-2022-49691", "CVE-2022-49720", "CVE-2022-49753", "CVE-2022-49821", "CVE-2022-49870", "CVE-2022-49915", "CVE-2023-52935", "CVE-2023-52973", "CVE-2023-52997", "CVE-2023-53005", "CVE-2023-53007", "CVE-2023-53019", "CVE-2023-53024", "CVE-2023-53032", "CVE-2023-53133", "CVE-2025-21772", "CVE-2025-21891", "CVE-2025-21993", "CVE-2025-21999", "CVE-2025-22055", "CVE-2025-22058", "CVE-2025-22125", "CVE-2025-37752", "CVE-2025-37785", "CVE-2025-37839");
  script_tag(name:"creation_date", value:"2025-07-11 04:39:00 +0000 (Fri, 11 Jul 2025)");
  script_version("2025-07-11T15:43:14+0000");
  script_tag(name:"last_modification", value:"2025-07-11 15:43:14 +0000 (Fri, 11 Jul 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-03-07 20:47:04 +0000 (Fri, 07 Mar 2025)");

  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2025-1800)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP10\-X86_64");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2025-1800");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2025-1800");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'kernel' package(s) announced via the EulerOS-SA-2025-1800 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"usbnet: fix memory leak in error case(CVE-2022-49657)

block: Fix handling of offline queues in blk_mq_alloc_request_hctx().(CVE-2022-49720)

partitions: mac: fix handling of bogus partition table(CVE-2025-21772)

icmp: Fix data-races around sysctl.(CVE-2022-49638)

erspan: do not assume transport header is always set(CVE-2022-49691)

net: mdio: unexport __init-annotated mdio_bus_init().(CVE-2022-49350)

tipc: check attribute length for bearer name(CVE-2022-49374)

RDMA/hfi1: Prevent panic when SDMA is disabled(CVE-2022-49429)

tcp/dccp: Fix a data-race around sysctl_tcp_fwmark_accept.(CVE-2022-49601)

ip: Fix data-races around sysctl_ip_fwd_use_pmtu.(CVE-2022-49604)

ip: Fix a data-race around sysctl_fwmark_reflect.(CVE-2022-49602)

igmp: Fix data-races around sysctl_igmp_llm_reports.(CVE-2022-49590)

tcp: Fix a data-race around sysctl_tcp_probe_interval.(CVE-2022-49593)

tcp: Fix a data-race around sysctl_tcp_probe_threshold.(CVE-2022-49595)

tcp: Fix data-races around sysctl_tcp_mtu_probing.(CVE-2022-49598)

usbnet: fix memory leak in error case(CVE-2022-49589)

tcp: Fix data-races around sysctl_tcp_fastopen.(CVE-2022-49586)

tcp: Fix data-races around sysctl_tcp_slow_start_after_idle.(CVE-2022-49572)

tcp: Fix a data-race around sysctl_tcp_notsent_lowat.(CVE-2022-49587)

tcp: Fix a data-race around sysctl_tcp_early_retrans.(CVE-2022-49573)

tcp: Fix data-races around sysctl_tcp_recovery.(CVE-2022-49574)

tcp: Fix data-races around sysctl_tcp_max_reordering.(CVE-2022-49571)

net: openvswitch: fix leak of nested actions(CVE-2022-49086)

bpf: Fix pointer-leak due to insufficient speculative store bypass mitigation(CVE-2023-53024)

mm/khugepaged: fix ->anon_vma race(CVE-2023-52935)

ipv4: prevent potential spectre v1 gadget in ip_metrics_convert().(CVE-2023-52997)

dmaengine: Fix double increment of client_count in dma_chan_get().(CVE-2022-49753)

vc_screen: move load of struct vc_data pointer in vcs_read() to avoid UAF(CVE-2023-52973)

ipvlan: ensure network headers are in skb linear part(CVE-2025-21891)

trace_events_hist: add check for return value of 'create_hist_field'(CVE-2023-53005)

net: mdio: validate parameter addr in mdiobus_get_phy().(CVE-2023-53019)

netfilter: ipset: Fix overflow before widen in the bitmap_ip_create() function.(CVE-2023-53032)

proc: fix UAF in proc_get_inode().(CVE-2025-21999)

ext4: fix OOB read when checking dotdot dir(CVE-2025-37785)

md/raid1,raid10: don't ignore IO flags(CVE-2025-22125)

net: fix geneve_opt length integer overflow(CVE-2025-22055)

udp: Fix memory accounting leak.(CVE-2025-22058)

mISDN: fix possible memory leak in mISDN_register_device().(CVE-2022-49915)

capabilities: fix undefined behavior in bit shift for CAP_TO_MASK(CVE-2022-49870)

bpf, sockmap: Fix an infinite loop error when len is 0 in tcp_bpf_recvmsg_parser().(CVE-2023-53133)

mISDN: fix possible memory leak in ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel' package(s) on Huawei EulerOS V2.0SP10(x86_64).");

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

if(release == "EULEROS-2.0SP10-x86_64") {

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~4.18.0~147.5.2.19.h1851.eulerosv2r10", rls:"EULEROS-2.0SP10-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-abi-stablelists", rpm:"kernel-abi-stablelists~4.18.0~147.5.2.19.h1851.eulerosv2r10", rls:"EULEROS-2.0SP10-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~4.18.0~147.5.2.19.h1851.eulerosv2r10", rls:"EULEROS-2.0SP10-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~4.18.0~147.5.2.19.h1851.eulerosv2r10", rls:"EULEROS-2.0SP10-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-perf", rpm:"python3-perf~4.18.0~147.5.2.19.h1851.eulerosv2r10", rls:"EULEROS-2.0SP10-x86_64"))) {
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
