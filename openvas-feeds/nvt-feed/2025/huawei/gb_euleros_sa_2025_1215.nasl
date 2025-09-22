# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2025.1215");
  script_cve_id("CVE-2021-47344", "CVE-2021-47345", "CVE-2022-48946", "CVE-2022-48949", "CVE-2022-48969", "CVE-2022-48978", "CVE-2022-48988", "CVE-2022-49000", "CVE-2022-49002", "CVE-2024-44958", "CVE-2024-45021", "CVE-2024-45025", "CVE-2024-46673", "CVE-2024-46739", "CVE-2024-46744", "CVE-2024-46750", "CVE-2024-46777", "CVE-2024-46826", "CVE-2024-46829", "CVE-2024-46859", "CVE-2024-47685", "CVE-2024-47696", "CVE-2024-47697", "CVE-2024-47698", "CVE-2024-47701", "CVE-2024-47742", "CVE-2024-47745", "CVE-2024-49855", "CVE-2024-49860", "CVE-2024-49881", "CVE-2024-49882", "CVE-2024-49883", "CVE-2024-49884", "CVE-2024-49889", "CVE-2024-49894", "CVE-2024-49959", "CVE-2024-49995", "CVE-2024-50033", "CVE-2024-50035", "CVE-2024-50036", "CVE-2024-50058", "CVE-2024-50073", "CVE-2024-50115", "CVE-2024-50154", "CVE-2024-50179", "CVE-2024-50195", "CVE-2024-50199", "CVE-2024-50258", "CVE-2024-50262", "CVE-2024-50278", "CVE-2024-50279", "CVE-2024-50301");
  script_tag(name:"creation_date", value:"2025-05-19 04:31:54 +0000 (Mon, 19 May 2025)");
  script_version("2025-05-19T05:40:31+0000");
  script_tag(name:"last_modification", value:"2025-05-19 05:40:31 +0000 (Mon, 19 May 2025)");
  script_tag(name:"cvss_base", value:"9.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-10-23 15:19:06 +0000 (Wed, 23 Oct 2024)");

  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2025-1215)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT\-2\.10\.0");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2025-1215");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2025-1215");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'kernel' package(s) announced via the EulerOS-SA-2025-1215 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"In the Linux kernel, the following vulnerability has been resolved: media: zr364xx: fix memory leak in zr364xx_start_readpipe syzbot reported memory leak in zr364xx driver. The problem was in non-freed urb in case of usb_submit_urb() fail. backtrace: [<ffffffff82baedf6>] kmalloc include/linux/slab.h:561 [inline] [<ffffffff82baedf6>] usb_alloc_urb+0x66/0xe0 drivers/usb/core/urb.c:74 [<ffffffff82f7cce8>] zr364xx_start_readpipe+0x78/0x130 drivers/media/usb/zr364xx/zr364xx.c:1022 [<ffffffff84251dfc>] zr364xx_board_init drivers/media/usb/zr364xx/zr364xx.c:1383 [inline] [<ffffffff84251dfc>] zr364xx_probe+0x6a3/0x851 drivers/media/usb/zr364xx/zr364xx.c:1516 [<ffffffff82bb6507>] usb_probe_interface+0x177/0x370 drivers/usb/core/driver.c:396 [<ffffffff826018a9>] really_probe+0x159/0x500 drivers/base/dd.c:576(CVE-2021-47344)

RDMA/cma: Fix rdma_resolve_route() memory leak(CVE-2021-47345)

udf: Fix preallocation discarding at indirect extent boundary(CVE-2022-48946)

igb: Initialize mailbox message for VF reset(CVE-2022-48949)

In the Linux kernel, the following vulnerability has been resolved: xen-netfront: Fix NULL sring after live migration A NAPI is setup for each network sring to poll data to kernel The sring with source host is destroyed before live migration and new sring with target host is setup after live migration. The NAPI for the old sring is not deleted until setup new sring with target host after migration. With busy_poll/busy_read enabled, the NAPI can be polled before got deleted when resume VM. BUG: unable to handle kernel NULL pointer dereference at 0000000000000008 IP: xennet_poll+0xae/0xd20 PGD 0 P4D 0 Oops: 0000 [#1] SMP PTI Call Trace: finish_task_switch+0x71/0x230 timerqueue_del+0x1d/0x40 hrtimer_try_to_cancel+0xb5/0x110 xennet_alloc_rx_buffers+0x2a0/0x2a0 napi_busy_loop+0xdb/0x270 sock_poll+0x87/0x90 do_sys_poll+0x26f/0x580 tracing_map_insert+0x1d4/0x2f0 event_hist_trigger+0x14a/0x260 finish_task_switch+0x71/0x230 __schedule+0x256/0x890 recalc_sigpending+0x1b/0x50 xen_sched_clock+0x15/0x20 __rb_reserve_next+0x12d/0x140 ring_buffer_lock_reserve+0x123/0x3d0 event_triggers_call+0x87/0xb0 trace_event_buffer_commit+0x1c4/0x210 xen_clocksource_get_cycles+0x15/0x20 ktime_get_ts64+0x51/0xf0 SyS_ppoll+0x160/0x1a0 SyS_ppoll+0x160/0x1a0 do_syscall_64+0x73/0x130 entry_SYSCALL_64_after_hwframe+0x41/0xa6 ... RIP: xennet_poll+0xae/0xd20 RSP: ffffb4f041933900 CR2: 0000000000000008 ---[ end trace f8601785b354351c ]--- xen frontend should remove the NAPIs for the old srings before live migration as the bond srings are destroyed There is a tiny window between the srings are set to NULL and the NAPIs are disabled, It is safe as the NAPI threads are still frozen at that time(CVE-2022-48969)

HID: core: fix shift-out-of-bounds in hid_report_raw_event(CVE-2022-48978)

memcg: fix possible use-after-free in memcg_write_event_control().(CVE-2022-48988)

In the Linux kernel, the ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel' package(s) on Huawei EulerOS Virtualization release 2.10.0.");

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

if(release == "EULEROSVIRT-2.10.0") {

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~4.18.0~147.5.2.19.h1766.eulerosv2r10", rls:"EULEROSVIRT-2.10.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-abi-stablelists", rpm:"kernel-abi-stablelists~4.18.0~147.5.2.19.h1766.eulerosv2r10", rls:"EULEROSVIRT-2.10.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~4.18.0~147.5.2.19.h1766.eulerosv2r10", rls:"EULEROSVIRT-2.10.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~4.18.0~147.5.2.19.h1766.eulerosv2r10", rls:"EULEROSVIRT-2.10.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-perf", rpm:"python3-perf~4.18.0~147.5.2.19.h1766.eulerosv2r10", rls:"EULEROSVIRT-2.10.0"))) {
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
