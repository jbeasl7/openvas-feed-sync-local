# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2024.1570");
  script_cve_id("CVE-2019-25162", "CVE-2021-33631", "CVE-2021-46904", "CVE-2021-46905", "CVE-2021-46906", "CVE-2021-46928", "CVE-2021-46934", "CVE-2021-46945", "CVE-2021-46952", "CVE-2021-46955", "CVE-2021-47006", "CVE-2021-47013", "CVE-2021-47015", "CVE-2021-47024", "CVE-2021-47040", "CVE-2021-47054", "CVE-2021-47056", "CVE-2021-47061", "CVE-2021-47063", "CVE-2021-47074", "CVE-2021-47076", "CVE-2021-47078", "CVE-2021-47082", "CVE-2022-48627", "CVE-2023-51042", "CVE-2023-51043", "CVE-2023-52435", "CVE-2023-52439", "CVE-2023-52458", "CVE-2023-52477", "CVE-2023-52486", "CVE-2023-52522", "CVE-2023-52527", "CVE-2023-52528", "CVE-2023-52578", "CVE-2023-52583", "CVE-2023-6531", "CVE-2024-0607", "CVE-2024-0639", "CVE-2024-1086", "CVE-2024-1151", "CVE-2024-26602");
  script_tag(name:"creation_date", value:"2024-05-10 04:12:42 +0000 (Fri, 10 May 2024)");
  script_version("2025-08-15T05:40:49+0000");
  script_tag(name:"last_modification", value:"2025-08-15 05:40:49 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-05 20:41:24 +0000 (Mon, 05 Feb 2024)");

  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2024-1570)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP10");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2024-1570");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2024-1570");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'kernel' package(s) announced via the EulerOS-SA-2024-1570 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"In the Linux kernel, the following vulnerability has been resolved: bus: qcom: Put child node before return Put child node before return to fix potential reference count leak. Generally, the reference count of child is incremented and decremented automatically in the macro for_each_available_child_of_node() and should be decremented manually if the loop is broken in loop body.(CVE-2021-47054)In the Linux kernel, the following vulnerability has been resolved: i2c: Fix a potential use after free Free the adap structure only after we are done using it. This patch just moves the put_device() down a bit to avoid the use after free. (CVE-2019-25162)In the Linux kernel, the following vulnerability has been resolved: net: bridge: use DEV_STATS_INC() syzbot/KCSAN reported data-races in br_handle_frame_finish() [1] This function can run from multiple cpus without mutual exclusion. Adopt SMP safe DEV_STATS_INC() to update dev->stats fields. Handles updates to dev->stats.tx_dropped while we are at it. [1] BUG: KCSAN: data-race in br_handle_frame_finish / br_handle_frame_finish read-write to 0xffff8881374b2178 of 8 bytes by interrupt on cpu 1: br_handle_frame_finish+0xd4f/0xef0 net/bridge/br_input.c:189 br_nf_hook_thresh+0x1ed/0x220 br_nf_pre_routing_finish_ipv6+0x50f/0x540 NF_HOOK include/linux/netfilter.h:304 [inline] br_nf_pre_routing_ipv6+0x1e3/0x2a0 net/bridge/br_netfilter_ipv6.c:178 br_nf_pre_routing+0x526/0xba0 net/bridge/br_netfilter_hooks.c:508 nf_hook_entry_hookfn include/linux/netfilter.h:144 [inline] nf_hook_bridge_pre net/bridge/br_input.c:272 [inline] br_handle_frame+0x4c9/0x940 net/bridge/br_input.c:417 __netif_receive_skb_core+0xa8a/0x21e0 net/core/dev.c:5417 __netif_receive_skb_one_core net/core/dev.c:5521 [inline] __netif_receive_skb+0x57/0x1b0 net/core/dev.c:5637 process_backlog+0x21f/0x380 net/core/dev.c:5965 __napi_poll+0x60/0x3b0 net/core/dev.c:6527 napi_poll net/core/dev.c:6594 [inline] net_rx_action+0x32b/0x750 net/core/dev.c:6727 __do_softirq+0xc1/0x265 kernel/softirq.c:553 run_ksoftirqd+0x17/0x20 kernel/softirq.c:921 smpboot_thread_fn+0x30a/0x4a0 kernel/smpboot.c:164 kthread+0x1d7/0x210 kernel/kthread.c:388 ret_from_fork+0x48/0x60 arch/x86/kernel/process.c:147 ret_from_fork_asm+0x11/0x20 arch/x86/entry/entry_64.S:304 read-write to 0xffff8881374b2178 of 8 bytes by interrupt on cpu 0: br_handle_frame_finish+0xd4f/0xef0 net/bridge/br_input.c:189 br_nf_hook_thresh+0x1ed/0x220 br_nf_pre_routing_finish_ipv6+0x50f/0x540 NF_HOOK include/linux/netfilter.h:304 [inline] br_nf_pre_routing_ipv6+0x1e3/0x2a0 net/bridge/br_netfilter_ipv6.c:178 br_nf_pre_routing+0x526/0xba0 net/bridge/br_netfilter_hooks.c:508 nf_hook_entry_hookfn include/linux/netfilter.h:144 [inline] nf_hook_bridge_pre net/bridge/br_input.c:272 [inline] br_handle_frame+0x4c9/0x940 net/bridge/br_input.c:417 __netif_receive_skb_core+0xa8a/0x21e0 net/core/dev.c:5417 __netif_receive_skb_one_core ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel' package(s) on Huawei EulerOS V2.0SP10.");

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

if(release == "EULEROS-2.0SP10") {

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~4.19.90~vhulk2211.3.0.h1746.eulerosv2r10", rls:"EULEROS-2.0SP10"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-abi-stablelists", rpm:"kernel-abi-stablelists~4.19.90~vhulk2211.3.0.h1746.eulerosv2r10", rls:"EULEROS-2.0SP10"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~4.19.90~vhulk2211.3.0.h1746.eulerosv2r10", rls:"EULEROS-2.0SP10"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~4.19.90~vhulk2211.3.0.h1746.eulerosv2r10", rls:"EULEROS-2.0SP10"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-perf", rpm:"python3-perf~4.19.90~vhulk2211.3.0.h1746.eulerosv2r10", rls:"EULEROS-2.0SP10"))) {
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
