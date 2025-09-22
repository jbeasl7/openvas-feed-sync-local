# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2024.1788");
  script_cve_id("CVE-2021-47036", "CVE-2021-47082", "CVE-2022-48627", "CVE-2023-52340", "CVE-2023-52434", "CVE-2023-52435", "CVE-2023-52438", "CVE-2023-52439", "CVE-2023-52443", "CVE-2023-52445", "CVE-2023-52447", "CVE-2023-52448", "CVE-2023-52451", "CVE-2023-52452", "CVE-2023-52454", "CVE-2023-52458", "CVE-2023-52462", "CVE-2023-52463", "CVE-2023-52464", "CVE-2023-52469", "CVE-2023-52474", "CVE-2023-52475", "CVE-2023-52477", "CVE-2023-52482", "CVE-2023-52504", "CVE-2023-52516", "CVE-2023-52528", "CVE-2023-52568", "CVE-2023-52575", "CVE-2024-0841", "CVE-2024-1086", "CVE-2024-1151", "CVE-2024-26581", "CVE-2024-26583", "CVE-2024-26584", "CVE-2024-26585", "CVE-2024-26586", "CVE-2024-26589", "CVE-2024-26593", "CVE-2024-26595", "CVE-2024-26597", "CVE-2024-26598", "CVE-2024-26601", "CVE-2024-26602", "CVE-2024-26603", "CVE-2024-26606");
  script_tag(name:"creation_date", value:"2024-06-03 04:15:31 +0000 (Mon, 03 Jun 2024)");
  script_version("2024-08-08T05:05:41+0000");
  script_tag(name:"last_modification", value:"2024-08-08 05:05:41 +0000 (Thu, 08 Aug 2024)");
  script_tag(name:"cvss_base", value:"7.7");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-03-15 14:21:29 +0000 (Fri, 15 Mar 2024)");

  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2024-1788)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP11");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2024-1788");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2024-1788");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'kernel' package(s) announced via the EulerOS-SA-2024-1788 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"In the Linux kernel, the following vulnerability has been resolved: KVM: arm64: vgic-its: Avoid potential UAF in LPI translation cache There is a potential UAF scenario in the case of an LPI translation cache hit racing with an operation that invalidates the cache, such as a DISCARD ITS command. The root of the problem is that vgic_its_check_cache() does not elevate the refcount on the vgic_irq before dropping the lock that serializes refcount changes. Have vgic_its_check_cache() raise the refcount on the returned vgic_irq and add the corresponding decrement after queueing the interrupt.(CVE-2024-26598)In the Linux kernel, the following vulnerability has been resolved: tun: avoid double free in tun_free_netdev Avoid double free in tun_free_netdev() by moving the dev->tstats and tun->security allocs to a new ndo_init routine (tun_net_init()) that will be called by register_netdevice(). ndo_init is paired with the desctructor (tun_free_netdev()), so if there's an error in register_netdevice() the destructor will handle the frees.(CVE-2021-47082)In the Linux kernel, the following vulnerability has been resolved: vt: fix memory overlapping when deleting chars in the buffer A memory overlapping copy occurs when deleting a long line. This memory overlapping copy can cause data corruption when scr_memcpyw is optimized to memcpy because memcpy does not ensure its behavior if the destination buffer overlaps with the source buffer. The line buffer is not always broken, because the memcpy utilizes the hardware acceleration, whose result is not deterministic. Fix this problem by using replacing the scr_memcpyw with scr_memmovew.(CVE-2022-48627)A flaw was found in hfi1 in the Linux Kernel. This issue is due to data corruption for user SDMA requests that have multiple payload iovecs where an iovec other than the tail iovec does not run up to the page boundary.(CVE-2023-52474)In the Linux kernel, the following vulnerability has been resolved: usb: hub: Guard against accesses to uninitialized BOS descriptors Many functions in drivers/usb/core/hub.c and drivers/usb/core/hub.h access fields inside udev->bos without checking if it was allocated and initialized. If usb_get_bos_descriptor() fails for whatever reason, udev->bos will be NULL and those accesses will result in a crash: BUG: kernel NULL pointer dereference, address: 0000000000000018 PGD 0 P4D 0 Oops: 0000 [#1] PREEMPT SMP NOPTI CPU: 5 PID: 17818 Comm: kworker/5:1 Tainted: G W 5.15.108-18910-gab0e1cb584e1 #1 <HASH:1f9e 1> Hardware name: Google Kindred/Kindred, BIOS Google_Kindred.12672.413.0 02/03/2021 Workqueue: usb_hub_wq hub_event RIP: 0010:hub_port_reset+0x193/0x788 Code: 89 f7 e8 20 f7 15 00 48 8b 43 08 80 b8 96 03 00 00 03 75 36 0f b7 88 92 03 00 00 81 f9 10 03 00 00 72 27 48 8b 80 a8 03 00 00 <48> 83 78 18 00 74 19 48 89 df 48 8b 75 b0 ba 02 00 00 00 4c 89 e9 RSP: 0018:ffffab740c53fcf8 EFLAGS: 00010246 RAX: 0000000000000000 ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel' package(s) on Huawei EulerOS V2.0SP11.");

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

if(release == "EULEROS-2.0SP11") {

  if(!isnull(res = isrpmvuln(pkg:"bpftool", rpm:"bpftool~5.10.0~60.18.0.50.h1209.eulerosv2r11", rls:"EULEROS-2.0SP11"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~5.10.0~60.18.0.50.h1209.eulerosv2r11", rls:"EULEROS-2.0SP11"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-abi-stablelists", rpm:"kernel-abi-stablelists~5.10.0~60.18.0.50.h1209.eulerosv2r11", rls:"EULEROS-2.0SP11"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~5.10.0~60.18.0.50.h1209.eulerosv2r11", rls:"EULEROS-2.0SP11"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~5.10.0~60.18.0.50.h1209.eulerosv2r11", rls:"EULEROS-2.0SP11"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-perf", rpm:"python3-perf~5.10.0~60.18.0.50.h1209.eulerosv2r11", rls:"EULEROS-2.0SP11"))) {
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
