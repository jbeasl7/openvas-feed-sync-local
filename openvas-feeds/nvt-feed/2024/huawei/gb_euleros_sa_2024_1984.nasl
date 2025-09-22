# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2024.1984");
  script_cve_id("CVE-2019-25162", "CVE-2020-36777", "CVE-2021-33631", "CVE-2021-46904", "CVE-2021-46905", "CVE-2021-46906", "CVE-2021-46915", "CVE-2021-46928", "CVE-2021-46934", "CVE-2021-46952", "CVE-2021-46955", "CVE-2021-46960", "CVE-2021-47006", "CVE-2021-47015", "CVE-2021-47041", "CVE-2021-47049", "CVE-2021-47056", "CVE-2021-47061", "CVE-2021-47063", "CVE-2021-47065", "CVE-2021-47070", "CVE-2021-47071", "CVE-2021-47073", "CVE-2021-47074", "CVE-2021-47078", "CVE-2021-47082", "CVE-2021-47110", "CVE-2022-48627", "CVE-2023-51042", "CVE-2023-51043", "CVE-2023-52435", "CVE-2023-52439", "CVE-2023-52445", "CVE-2023-52448", "CVE-2023-52454", "CVE-2023-52458", "CVE-2023-52475", "CVE-2023-52476", "CVE-2023-52477", "CVE-2023-52478", "CVE-2023-52486", "CVE-2023-52504", "CVE-2023-52522", "CVE-2023-52528", "CVE-2023-52530", "CVE-2023-52574", "CVE-2023-52578", "CVE-2023-52583", "CVE-2024-0607", "CVE-2024-0639", "CVE-2024-1086", "CVE-2024-1151", "CVE-2024-26585", "CVE-2024-26586", "CVE-2024-26589", "CVE-2024-26595", "CVE-2024-26602");
  script_tag(name:"creation_date", value:"2024-07-19 04:39:10 +0000 (Fri, 19 Jul 2024)");
  script_version("2024-08-08T05:05:41+0000");
  script_tag(name:"last_modification", value:"2024-08-08 05:05:41 +0000 (Thu, 08 Aug 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-03-18 17:56:56 +0000 (Mon, 18 Mar 2024)");

  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2024-1984)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT\-2\.10\.0");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2024-1984");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2024-1984");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'kernel' package(s) announced via the EulerOS-SA-2024-1984 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"In the Linux kernel, the following vulnerability has been resolved: tun: avoid double free in tun_free_netdev Avoid double free in tun_free_netdev() by moving the dev->tstats and tun->security allocs to a new ndo_init routine (tun_net_init()) that will be called by register_netdevice(). ndo_init is paired with the desctructor (tun_free_netdev()), so if there's an error in register_netdevice() the destructor will handle the frees. BUG: KASAN: double-free or invalid-free in selinux_tun_dev_free_security+0x1a/0x20 security/selinux/hooks.c:5605 CPU: 0 PID: 25750 Comm: syz-executor416 Not tainted 5.16.0-rc2-syzk #1 Hardware name: Red Hat KVM, BIOS Call Trace: <TASK> __dump_stack lib/dump_stack.c:88 [inline] dump_stack_lvl+0x89/0xb5 lib/dump_stack.c:106 print_address_description.constprop.9+0x28/0x160 mm/kasan/report.c:247 kasan_report_invalid_free+0x55/0x80 mm/kasan/report.c:372 ____kasan_slab_free mm/kasan/common.c:346 [inline] __kasan_slab_free+0x107/0x120 mm/kasan/common.c:374 kasan_slab_free include/linux/kasan.h:235 [inline] slab_free_hook mm/slub.c:1723 [inline] slab_free_freelist_hook mm/slub.c:1749 [inline] slab_free mm/slub.c:3513 [inline] kfree+0xac/0x2d0 mm/slub.c:4561 selinux_tun_dev_free_security+0x1a/0x20 security/selinux/hooks.c:5605 security_tun_dev_free_security+0x4f/0x90 security/security.c:2342 tun_free_netdev+0xe6/0x150 drivers
et/tun.c:2215 netdev_run_todo+0x4df/0x840 net/core/dev.c:10627 rtnl_unlock+0x13/0x20 net/core/rtnetlink.c:112 __tun_chr_ioctl+0x80c/0x2870 drivers
et/tun.c:3302 tun_chr_ioctl+0x2f/0x40 drivers
et/tun.c:3311 vfs_ioctl fs/ioctl.c:51 [inline] __do_sys_ioctl fs/ioctl.c:874 [inline] __se_sys_ioctl fs/ioctl.c:860 [inline] __x64_sys_ioctl+0x19d/0x220 fs/ioctl.c:860 do_syscall_x64 arch/x86/entry/common.c:50 [inline] do_syscall_64+0x3a/0x80 arch/x86/entry/common.c:80 entry_SYSCALL_64_after_hwframe+0x44/0xae(CVE-2021-47082)

In the Linux kernel, the following vulnerability has been resolved: x86/kvm: Disable kvmclock on all CPUs on shutdown Currenly, we disable kvmclock from machine_shutdown() hook and this only happens for boot CPU. We need to disable it for all CPUs to guard against memory corruption e.g. on restore from hibernate. Note, writing '0' to kvmclock MSR doesn't clear memory location, it just prevents hypervisor from updating the location so for the short while after write and while CPU is still alive, the clock remains usable and correct so we don't need to switch to some other clocksource.(CVE-2021-47110)

In the Linux kernel, the following vulnerability has been resolved: net: bridge: use DEV_STATS_INC() syzbot/KCSAN reported data-races in br_handle_frame_finish() [1] This function can run from multiple cpus without mutual exclusion. Adopt SMP safe DEV_STATS_INC() to update dev->stats fields. Handles updates to dev->stats.tx_dropped while we are at it. [1] BUG: KCSAN: data-race in br_handle_frame_finish / ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel' package(s) on Huawei EulerOS Virtualization release 2.10.0.");

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

if(release == "EULEROSVIRT-2.10.0") {

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~4.18.0~147.5.2.19.h1506.eulerosv2r10", rls:"EULEROSVIRT-2.10.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-abi-stablelists", rpm:"kernel-abi-stablelists~4.18.0~147.5.2.19.h1506.eulerosv2r10", rls:"EULEROSVIRT-2.10.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~4.18.0~147.5.2.19.h1506.eulerosv2r10", rls:"EULEROSVIRT-2.10.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~4.18.0~147.5.2.19.h1506.eulerosv2r10", rls:"EULEROSVIRT-2.10.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-perf", rpm:"python3-perf~4.18.0~147.5.2.19.h1506.eulerosv2r10", rls:"EULEROSVIRT-2.10.0"))) {
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
