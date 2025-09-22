# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2024.2308");
  script_cve_id("CVE-2021-47094", "CVE-2021-47101", "CVE-2021-47105", "CVE-2021-47182", "CVE-2021-47212", "CVE-2023-52467", "CVE-2023-52478", "CVE-2023-52492", "CVE-2023-52498", "CVE-2023-52515", "CVE-2023-52612", "CVE-2023-52619", "CVE-2023-52620", "CVE-2023-52621", "CVE-2023-52622", "CVE-2023-52623", "CVE-2023-52628", "CVE-2023-52646", "CVE-2023-6536", "CVE-2024-23307", "CVE-2024-24861", "CVE-2024-25739", "CVE-2024-26633", "CVE-2024-26635", "CVE-2024-26636", "CVE-2024-26640", "CVE-2024-26641", "CVE-2024-26642", "CVE-2024-26643", "CVE-2024-26645", "CVE-2024-26659", "CVE-2024-26663", "CVE-2024-26665", "CVE-2024-26668", "CVE-2024-26669", "CVE-2024-26671", "CVE-2024-26673", "CVE-2024-26675", "CVE-2024-26679", "CVE-2024-26680", "CVE-2024-26686", "CVE-2024-26687", "CVE-2024-26688", "CVE-2024-26689", "CVE-2024-26695", "CVE-2024-26698", "CVE-2024-26704", "CVE-2024-26720", "CVE-2024-26733", "CVE-2024-26734", "CVE-2024-26735", "CVE-2024-26739", "CVE-2024-26740", "CVE-2024-26743", "CVE-2024-26744", "CVE-2024-26747", "CVE-2024-26752", "CVE-2024-26759", "CVE-2024-26763", "CVE-2024-26764", "CVE-2024-26766", "CVE-2024-26769", "CVE-2024-26772", "CVE-2024-26773", "CVE-2024-26774", "CVE-2024-26798", "CVE-2024-26804", "CVE-2024-26805", "CVE-2024-26808", "CVE-2024-26809", "CVE-2024-26810", "CVE-2024-26812", "CVE-2024-26813", "CVE-2024-26814", "CVE-2024-26833", "CVE-2024-26835", "CVE-2024-26839", "CVE-2024-26840", "CVE-2024-26851", "CVE-2024-26855", "CVE-2024-26859", "CVE-2024-26862", "CVE-2024-26870", "CVE-2024-26872", "CVE-2024-26875", "CVE-2024-26878", "CVE-2024-26882", "CVE-2024-26883", "CVE-2024-26884", "CVE-2024-26885", "CVE-2024-26894", "CVE-2024-26898", "CVE-2024-26900", "CVE-2024-26901", "CVE-2024-26920", "CVE-2024-27437");
  script_tag(name:"creation_date", value:"2024-09-03 13:47:15 +0000 (Tue, 03 Sep 2024)");
  script_version("2024-09-04T05:16:32+0000");
  script_tag(name:"last_modification", value:"2024-09-04 05:16:32 +0000 (Wed, 04 Sep 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-04-29 19:31:26 +0000 (Mon, 29 Apr 2024)");

  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2024-2308)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT\-2\.12\.1");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2024-2308");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2024-2308");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'kernel' package(s) announced via the EulerOS-SA-2024-2308 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A flaw was found in the Linux kernel's NVMe driver. This issue may allow an unauthenticated malicious actor to send a set of crafted TCP packages when using NVMe over TCP, leading the NVMe driver to a NULL pointer dereference in the NVMe driver, causing kernel panic and a denial of service.(CVE-2023-6536)

A race condition was found in the Linux kernel's media/xc4000 device driver in xc4000 xc4000_get_frequency() function. This can result in return value overflow issue, possibly leading to malfunction or denial of service issue.(CVE-2024-24861)

create_empty_lvol in drivers/mtd/ubi/vtbl.c in the Linux kernel through 6.7.4 can attempt to allocate zero bytes, and crash, because of a missing check for ubi->leb_size.(CVE-2024-25739)

In the Linux kernel, the following vulnerability has been resolved: ACPI: processor_idle: Fix memory leak in acpi_processor_power_exit() After unregistering the CPU idle device, the memory associated with it is not freed, leading to a memory leak: unreferenced object 0xffff896282f6c000 (size 1024): comm 'swapper/0', pid 1, jiffies 4294893170 hex dump (first 32 bytes): 00 00 00 00 0b 00 00 00 00 00 00 00 00 00 00 00 ................ 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ................ backtrace (crc 8836a742): [<ffffffff993495ed>] kmalloc_trace+0x29d/0x340 [<ffffffff9972f3b3>] acpi_processor_power_init+0xf3/0x1c0 [<ffffffff9972d263>] __acpi_processor_start+0xd3/0xf0 [<ffffffff9972d2bc>] acpi_processor_start+0x2c/0x50 [<ffffffff99805872>] really_probe+0xe2/0x480 [<ffffffff99805c98>] __driver_probe_device+0x78/0x160 [<ffffffff99805daf>] driver_probe_device+0x1f/0x90 [<ffffffff9980601e>] __driver_attach+0xce/0x1c0 [<ffffffff99803170>] bus_for_each_dev+0x70/0xc0 [<ffffffff99804822>] bus_add_driver+0x112/0x210 [<ffffffff99807245>] driver_register+0x55/0x100 [<ffffffff9aee4acb>] acpi_processor_driver_init+0x3b/0xc0 [<ffffffff990012d1>] do_one_initcall+0x41/0x300 [<ffffffff9ae7c4b0>] kernel_init_freeable+0x320/0x470 [<ffffffff99b231f6>] kernel_init+0x16/0x1b0 [<ffffffff99042e6d>] ret_from_fork+0x2d/0x50 Fix this by freeing the CPU idle device after unregistering (CVE-2024-26894)

In the Linux kernel, the following vulnerability has been resolved: aio: fix mremap after fork null-deref Commit e4a0d3e720e7 ('aio: Make it possible to remap aio ring') introduced a null-deref if mremap is called on an old aio mapping after fork as mm->ioctx_table will be set to NULL. (CVE-2023-52646)

In the Linux kernel, the following vulnerability has been resolved: arp: Prevent overflow in arp_req_get(). syzkaller reported an overflown write in arp_req_get(). [0] When ioctl(SIOCGARP) is issued, arp_req_get() looks up an neighbour entry and copies neigh->ha to struct arpreq.arp_ha.sa_data. The arp_ha here is struct sockaddr, not struct sockaddr_storage, so the sa_data buffer is just 14 bytes. In the splat below, 2 bytes are overflown to the next int field, ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel' package(s) on Huawei EulerOS Virtualization release 2.12.1.");

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

if(release == "EULEROSVIRT-2.12.1") {

  if(!isnull(res = isrpmvuln(pkg:"bpftool", rpm:"bpftool~5.10.0~136.12.0.86.h1837.eulerosv2r12", rls:"EULEROSVIRT-2.12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~5.10.0~136.12.0.86.h1837.eulerosv2r12", rls:"EULEROSVIRT-2.12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-abi-stablelists", rpm:"kernel-abi-stablelists~5.10.0~136.12.0.86.h1837.eulerosv2r12", rls:"EULEROSVIRT-2.12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~5.10.0~136.12.0.86.h1837.eulerosv2r12", rls:"EULEROSVIRT-2.12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~5.10.0~136.12.0.86.h1837.eulerosv2r12", rls:"EULEROSVIRT-2.12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-perf", rpm:"python3-perf~5.10.0~136.12.0.86.h1837.eulerosv2r12", rls:"EULEROSVIRT-2.12.1"))) {
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
