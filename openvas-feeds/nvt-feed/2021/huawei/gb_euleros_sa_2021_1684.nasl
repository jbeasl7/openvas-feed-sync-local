# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2021.1684");
  script_cve_id("CVE-2018-9517", "CVE-2019-19338", "CVE-2019-20934", "CVE-2019-3900", "CVE-2020-0543", "CVE-2020-10690", "CVE-2020-12351", "CVE-2020-14305", "CVE-2020-15436", "CVE-2020-15437", "CVE-2020-25669", "CVE-2020-25704", "CVE-2020-27777", "CVE-2020-27786", "CVE-2020-28915", "CVE-2020-28974", "CVE-2020-29370", "CVE-2020-29371", "CVE-2020-29660", "CVE-2020-29661", "CVE-2020-36158", "CVE-2020-4788");
  script_tag(name:"creation_date", value:"2021-03-24 06:54:04 +0000 (Wed, 24 Mar 2021)");
  script_version("2024-02-05T14:36:56+0000");
  script_tag(name:"last_modification", value:"2024-02-05 14:36:56 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-12-10 14:55:40 +0000 (Thu, 10 Dec 2020)");

  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2021-1684)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP5");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2021-1684");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2021-1684");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'kernel' package(s) announced via the EulerOS-SA-2021-1684 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"mwifiex_cmd_802_11_ad_hoc_start in drivers/net/wireless/marvell/mwifiex/join.c in the Linux kernel through 5.10.4 might allow remote attackers to execute arbitrary code via a long SSID value, aka CID-5c455c5ab332.(CVE-2020-36158)

Incomplete cleanup from specific special register read operations in some Intel(R) Processors may allow an authenticated user to potentially enable information disclosure via local access.(CVE-2020-0543)

An infinite loop issue was found in the vhost_net kernel module in Linux Kernel up to and including v5.1-rc6, while handling incoming packets in handle_rx(). It could occur if one end sends packets faster than the other end can process them. A guest user, maybe remote one, could use this flaw to stall the vhost_net kernel thread, resulting in a DoS scenario.(CVE-2019-3900)

In pppol2tp_connect, there is possible memory corruption due to a use after free. This could lead to local escalation of privilege with System execution privileges needed. User interaction is not needed for exploitation. Product: Android. Versions: Android kernel. Android ID: A-38159931.(CVE-2018-9517)

A flaw was found in the fix for CVE-2019-11135, in the Linux upstream kernel versions before 5.5 where, the way Intel CPUs handle speculative execution of instructions when a TSX Asynchronous Abort (TAA) error occurs. When a guest is running on a host CPU affected by the TAA flaw (TAA_NO=0), but is not affected by the MDS issue (MDS_NO=1), the guest was to clear the affected buffers by using a VERW instruction mechanism. But when the MDS_NO=1 bit was exported to the guests, the guests did not use the VERW mechanism to clear the affected buffers. This issue affects guests running on Cascade Lake CPUs and requires that host has 'TSX' enabled. Confidentiality of data is the highest threat associated with this vulnerability.(CVE-2019-19338)

There is a use-after-free in kernel versions before 5.5 due to a race condition between the release of ptp_clock and cdev while resource deallocation. When a (high privileged) process allocates a ptp device file (like /dev/ptpX) and voluntarily goes to sleep. During this time if the underlying device is removed, it can cause an exploitable condition as the process wakes up to terminate and clean all attached files. The system crashes due to the cdev structure being invalid (as already freed) which is pointed to by the inode.(CVE-2020-10690)

Improper input validation in BlueZ may allow an unauthenticated user to potentially enable escalation of privilege via adjacent access.(CVE-2020-12351)

A flaw was found in the Linux kernels implementation of MIDI, where an attacker with a local account and the permissions to issue an ioctl commands to midi devices, could trigger a use-after-free. A write to this specific memory while freed and before use could cause the flow of execution to change and possibly allow for memory corruption or privilege ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~3.10.0~862.14.1.5.h520.eulerosv2r7", rls:"EULEROS-2.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~3.10.0~862.14.1.5.h520.eulerosv2r7", rls:"EULEROS-2.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~3.10.0~862.14.1.5.h520.eulerosv2r7", rls:"EULEROS-2.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~3.10.0~862.14.1.5.h520.eulerosv2r7", rls:"EULEROS-2.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~3.10.0~862.14.1.5.h520.eulerosv2r7", rls:"EULEROS-2.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~3.10.0~862.14.1.5.h520.eulerosv2r7", rls:"EULEROS-2.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~3.10.0~862.14.1.5.h520.eulerosv2r7", rls:"EULEROS-2.0SP5"))) {
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
