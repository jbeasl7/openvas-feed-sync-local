# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2024.2070");
  script_cve_id("CVE-2021-33631", "CVE-2021-46936", "CVE-2021-46952", "CVE-2023-51043", "CVE-2023-52435", "CVE-2023-52439", "CVE-2023-52445", "CVE-2024-0607");
  script_tag(name:"creation_date", value:"2024-08-07 04:41:58 +0000 (Wed, 07 Aug 2024)");
  script_version("2024-08-08T05:05:41+0000");
  script_tag(name:"last_modification", value:"2024-08-08 05:05:41 +0000 (Thu, 08 Aug 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-03-14 20:13:50 +0000 (Thu, 14 Mar 2024)");

  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2024-2070)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP5");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2024-2070");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2024-2070");
  script_xref(name:"URL", value:"https://groups.google.com/g/syzkaller/c/p1tn-_Kc6l4/m/smuL_FMAAgAJ?pli=1");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'kernel' package(s) announced via the EulerOS-SA-2024-2070 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"In the Linux kernel, the following vulnerability has been resolved: net: fix use-after-free in tw_timer_handler A real world panic issue was found as follow in Linux 5.4. BUG: unable to handle page fault for address: ffffde49a863de28 PGD 7e6fe62067 P4D 7e6fe62067 PUD 7e6fe63067 PMD f51e064067 PTE 0 RIP: 0010:tw_timer_handler+0x20/0x40 Call Trace: <IRQ> call_timer_fn+0x2b/0x120 run_timer_softirq+0x1ef/0x450 __do_softirq+0x10d/0x2b8 irq_exit+0xc7/0xd0 smp_apic_timer_interrupt+0x68/0x120 apic_timer_interrupt+0xf/0x20 This issue was also reported since 2017 in the thread [1], unfortunately, the issue was still can be reproduced after fixing DCCP. The ipv4_mib_exit_net is called before tcp_sk_exit_batch when a net namespace is destroyed since tcp_sk_ops is registered befrore ipv4_mib_ops, which means tcp_sk_ops is in the front of ipv4_mib_ops in the list of pernet_list. There will be a use-after-free on net->mib.net_statistics in tw_timer_handler after ipv4_mib_exit_net if there are some inflight time-wait timers. This bug is not introduced by commit f2bf415cfed7 ('mib: add net to NET_ADD_STATS_BH') since the net_statistics is a global variable instead of dynamic allocation and freeing. Actually, commit 61a7e26028b9 ('mib: put net statistics on struct net') introduces the bug since it put net statistics on struct net and free it when net namespace is destroyed. Moving init_ipv4_mibs() to the front of tcp_init() to fix this bug and replace pr_crit() with panic() since continuing is meaningless when init_ipv4_mibs() fails. [1] [link moved to references](CVE-2021-46936)

In the Linux kernel, the following vulnerability has been resolved: NFS: fs_context: validate UDP retrans to prevent shift out-of-bounds Fix shift out-of-bounds in xprt_calc_majortimeo(). This is caused by a garbage timeout (retrans) mount option being passed to nfs mount, in this case from syzkaller. If the protocol is XPRT_TRANSPORT_UDP, then 'retrans' is a shift value for a 64-bit long integer, so 'retrans' cannot be >= 64. If it is >= 64, fail the mount and return an error.(CVE-2021-46952)

In the Linux kernel, the following vulnerability has been resolved: media: pvrusb2: fix use after free on context disconnection Upon module load, a kthread is created targeting the pvr2_context_thread_func function, which may call pvr2_context_destroy and thus call kfree() on the context object. However, that might happen before the usb hub_event handler is able to notify the driver. This patch adds a sanity check before the invalid read reported by syzbot, within the context disconnection call stack.(CVE-2023-52445)

In the Linux kernel, the following vulnerability has been resolved: net: prevent mss overflow in skb_segment() Once again syzbot is able to crash the kernel in skb_segment() [1] GSO_BY_FRAGS is a forbidden value, but unfortunately the following computation in ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel' package(s) on Huawei EulerOS V2.0SP5.");

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

if(release == "EULEROS-2.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~3.10.0~862.14.1.5.h839.eulerosv2r7", rls:"EULEROS-2.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~3.10.0~862.14.1.5.h839.eulerosv2r7", rls:"EULEROS-2.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~3.10.0~862.14.1.5.h839.eulerosv2r7", rls:"EULEROS-2.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~3.10.0~862.14.1.5.h839.eulerosv2r7", rls:"EULEROS-2.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~3.10.0~862.14.1.5.h839.eulerosv2r7", rls:"EULEROS-2.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~3.10.0~862.14.1.5.h839.eulerosv2r7", rls:"EULEROS-2.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~3.10.0~862.14.1.5.h839.eulerosv2r7", rls:"EULEROS-2.0SP5"))) {
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
