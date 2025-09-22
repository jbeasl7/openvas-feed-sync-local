# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2024.2038");
  script_cve_id("CVE-2019-25162", "CVE-2021-33631", "CVE-2021-46904", "CVE-2021-46905", "CVE-2021-46906", "CVE-2021-46915", "CVE-2021-46921", "CVE-2021-46928", "CVE-2021-46932", "CVE-2021-46934", "CVE-2021-46936", "CVE-2021-46938", "CVE-2021-46939", "CVE-2021-46945", "CVE-2021-46952", "CVE-2021-46953", "CVE-2021-46955", "CVE-2021-46960", "CVE-2021-46988", "CVE-2021-46992", "CVE-2021-47006", "CVE-2021-47010", "CVE-2021-47013", "CVE-2021-47015", "CVE-2021-47024", "CVE-2021-47054", "CVE-2021-47060", "CVE-2021-47061", "CVE-2021-47063", "CVE-2021-47074", "CVE-2021-47076", "CVE-2021-47077", "CVE-2021-47078", "CVE-2021-47082", "CVE-2021-47091", "CVE-2021-47101", "CVE-2021-47131", "CVE-2021-47142", "CVE-2021-47144", "CVE-2021-47146", "CVE-2021-47166", "CVE-2021-47167", "CVE-2021-47168", "CVE-2021-47170", "CVE-2021-47171", "CVE-2021-47182", "CVE-2021-47194", "CVE-2021-47203", "CVE-2022-48619", "CVE-2022-48627", "CVE-2023-51042", "CVE-2023-51043", "CVE-2023-52340", "CVE-2023-52435", "CVE-2023-52439", "CVE-2023-52458", "CVE-2023-52464", "CVE-2023-52469", "CVE-2023-52477", "CVE-2023-52478", "CVE-2023-52486", "CVE-2023-52515", "CVE-2023-52522", "CVE-2023-52527", "CVE-2023-52528", "CVE-2023-52530", "CVE-2023-52574", "CVE-2023-52578", "CVE-2023-52583", "CVE-2023-52587", "CVE-2023-52595", "CVE-2023-52597", "CVE-2023-52612", "CVE-2023-52615", "CVE-2023-52619", "CVE-2023-52620", "CVE-2023-52622", "CVE-2023-52623", "CVE-2023-7042", "CVE-2024-0607", "CVE-2024-0775", "CVE-2024-1086", "CVE-2024-1151", "CVE-2024-23307", "CVE-2024-24855", "CVE-2024-25739", "CVE-2024-26597", "CVE-2024-26598", "CVE-2024-26602", "CVE-2024-26614", "CVE-2024-26633", "CVE-2024-26635", "CVE-2024-26640", "CVE-2024-26641", "CVE-2024-26642", "CVE-2024-26645", "CVE-2024-26668", "CVE-2024-26671", "CVE-2024-26675", "CVE-2024-26679", "CVE-2024-26686", "CVE-2024-26704", "CVE-2024-26720", "CVE-2024-26733", "CVE-2024-26735", "CVE-2024-26739", "CVE-2024-26740", "CVE-2024-26743", "CVE-2024-26744", "CVE-2024-26752", "CVE-2024-26759", "CVE-2024-26763", "CVE-2024-26772", "CVE-2024-26773", "CVE-2024-26779", "CVE-2024-26804", "CVE-2024-26805", "CVE-2024-26810", "CVE-2024-26812", "CVE-2024-26813", "CVE-2024-26828", "CVE-2024-26840", "CVE-2024-26845", "CVE-2024-26851", "CVE-2024-26859", "CVE-2024-26872", "CVE-2024-26882", "CVE-2024-26883", "CVE-2024-26884", "CVE-2024-26894", "CVE-2024-26901", "CVE-2024-26915", "CVE-2024-26922", "CVE-2024-27437");
  script_tag(name:"creation_date", value:"2024-07-22 09:23:46 +0000 (Mon, 22 Jul 2024)");
  script_version("2024-08-08T05:05:41+0000");
  script_tag(name:"last_modification", value:"2024-08-08 05:05:41 +0000 (Thu, 08 Aug 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-04-29 20:03:04 +0000 (Mon, 29 Apr 2024)");

  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2024-2038)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP8");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2024-2038");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2024-2038");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'kernel' package(s) announced via the EulerOS-SA-2024-2038 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"In the Linux kernel, the following vulnerability has been resolved: IB/ipoib: Fix mcast list locking Releasing the `priv->lock` while iterating the `priv->multicast_list` in `ipoib_mcast_join_task()` opens a window for `ipoib_mcast_dev_flush()` to remove the items while in the middle of iteration. If the mcast is removed while the lock was dropped, the for loop spins forever resulting in a hard lockup(CVE-2023-52587)

In the Linux kernel, the following vulnerability has been resolved: netfilter: nftables: avoid overflows in nft_hash_buckets() Number of buckets being stored in 32bit variables, we have to ensure that no overflows occur in nft_hash_buckets() syzbot injected a size == 0x40000000 and reported: UBSAN: shift-out-of-bounds in ./include/linux/log2.h:57:13 shift exponent 64 is too large for 64-bit type 'long unsigned int' CPU: 1 PID: 29539 Comm: syz-executor.4 Not tainted 5.12.0-rc7-syzkaller #0 Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 01/01/2011(CVE-2021-46992)

In the Linux kernel, the following vulnerability has been resolved: SUNRPC: Fix a suspicious RCU usage warning I received the following warning while running cthon against an ontap server running pNFS: [ 57.202521] ============================= [ 57.202522] WARNING: suspicious RCU usage [ 57.202523] 6.7.0-rc3-g2cc14f52aeb7 #41492 Not tainted [ 57.202525] ----------------------------- [ 57.202525] net/sunrpc/xprtmultipath.c:349 RCU-list traversed in non-reader section!! [ 57.202527] other info that might help us debug this: [ 57.202528] rcu_scheduler_active = 2, debug_locks = 1 [ 57.202529] no locks held by test5/3567. [ 57.202530] stack backtrace: [ 57.202532] CPU: 0 PID: 3567 Comm: test5 Not tainted 6.7.0-rc3-g2cc14f52aeb7 #41492 5b09971b4965c0aceba19f3eea324a4a806e227e [ 57.202534] Hardware name: QEMU Standard PC (Q35 + ICH9, 2009), BIOS unknown 2/2/2022 [ 57.202536] (CVE-2023-52623)

In the Linux kernel, the following vulnerability has been resolved: l2tp: pass correct message length to ip6_append_data l2tp_ip6_sendmsg needs to avoid accounting for the transport header twice when splicing more data into an already partially-occupied skbuff. To manage this, we check whether the skbuff contains data using skb_queue_empty when deciding how much data to append using ip6_append_data. However, the code which performed the calculation was incorrect: ulen = len + skb_queue_empty(&sk->sk_write_queue) ? transhdrlen : 0, ...due to C operator precedence, this ends up setting ulen to transhdrlen for messages with a non-zero length, which results in corrupted packets on the wire. Add parentheses to correct the calculation in line with the original intent.(CVE-2024-26752)

In the Linux kernel, the following vulnerability has been resolved: net/sched: act_mirred: use the backlog for mirred ingress The test Davide added in commit ca22da2fbd69 ('act_mirred: use the backlog for ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel' package(s) on Huawei EulerOS V2.0SP8.");

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

if(release == "EULEROS-2.0SP8") {

  if(!isnull(res = isrpmvuln(pkg:"bpftool", rpm:"bpftool~4.19.36~vhulk1907.1.0.h1635.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~4.19.36~vhulk1907.1.0.h1635.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.19.36~vhulk1907.1.0.h1635.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~4.19.36~vhulk1907.1.0.h1635.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~4.19.36~vhulk1907.1.0.h1635.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~4.19.36~vhulk1907.1.0.h1635.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~4.19.36~vhulk1907.1.0.h1635.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~4.19.36~vhulk1907.1.0.h1635.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-perf", rpm:"python3-perf~4.19.36~vhulk1907.1.0.h1635.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
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
