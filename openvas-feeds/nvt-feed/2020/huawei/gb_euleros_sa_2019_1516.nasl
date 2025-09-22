# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2019.1516");
  script_cve_id("CVE-2013-7265", "CVE-2014-0069", "CVE-2014-4027", "CVE-2015-5283", "CVE-2016-2065", "CVE-2016-2549", "CVE-2016-3672", "CVE-2016-4486", "CVE-2016-5344", "CVE-2016-6213", "CVE-2016-6480", "CVE-2016-9555", "CVE-2016-9685", "CVE-2017-1000363", "CVE-2017-13715", "CVE-2017-15102", "CVE-2017-17862", "CVE-2017-7308", "CVE-2017-8925", "CVE-2018-10074");
  script_tag(name:"creation_date", value:"2020-01-23 12:01:34 +0000 (Thu, 23 Jan 2020)");
  script_version("2024-02-05T14:36:56+0000");
  script_tag(name:"last_modification", value:"2024-02-05 14:36:56 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-09-08 20:55:07 +0000 (Fri, 08 Sep 2017)");

  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2019-1516)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRTARM64\-3\.0\.1\.0");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2019-1516");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2019-1516");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'kernel' package(s) announced via the EulerOS-SA-2019-1516 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The hi3660_stub_clk_probe function in drivers/clk/hisilicon/clk-hi3660-stub.c in the Linux kernel before 4.16 allows local users to cause a denial of service (NULL pointer dereference) by triggering a failure of resource retrieval.(CVE-2018-10074)

An information leak flaw was found in the RAM Disks Memory Copy (rd_mcp) backend driver of the iSCSI Target subsystem of the Linux kernel. A privileged user could use this flaw to leak the contents of kernel memory to an iSCSI initiator remote client.(CVE-2014-4027)

It was found that in the Linux kernel version 4.2-rc1 to 4.3-rc1, a use of uninitialized 'n_proto', 'ip_proto', and 'thoff' variables in __skb_flow_dissect() function can lead to a remote denial-of-service via malformed MPLS packet.(CVE-2017-13715)

It was found that the packet_set_ring() function of the Linux kernel's networking implementation did not properly validate certain block-size data. A local attacker with CAP_NET_RAW capability could use this flaw to trigger a buffer overflow, resulting in the crash of the system. Due to the nature of the flaw, privilege escalation cannot be fully ruled out.(CVE-2017-7308)

A weakness was found in the Linux ASLR implementation. Any user able to running 32-bit applications in a x86 machine can disable ASLR by setting the RLIMIT_STACK resource to unlimited.(CVE-2016-3672)

sound/soc/msm/qdsp6v2/msm-audio-effects-q6-v2.c in the MSM QDSP6 audio driver for the Linux kernel 3.x, as used in Qualcomm Innovation Center (QuIC) Android contributions for MSM devices and other products, allows attackers to cause a denial of service (out-of-bounds write and memory corruption) or possibly have unspecified other impact via a crafted application that makes an ioctl call triggering incorrect use of a parameters pointer.(CVE-2016-2065)

A race condition flaw was found in the ioctl_send_fib() function in the Linux kernel's aacraid implementation. A local attacker could use this flaw to cause a denial of service (out-of-bounds access or system crash) by changing a certain size value.(CVE-2016-6480)

The omninet_open function in drivers/usb/serial/omninet.c in the Linux kernel before 4.10.4 allows local users to cause a denial of service (tty exhaustion) by leveraging reference count mishandling.(CVE-2017-8925)

The tower_probe function in drivers/usb/misc/legousbtower.c in the Linux kernel before 4.8.1 allows local users (who are physically proximate for inserting a crafted USB device) to gain privileges by leveraging a write-what-where condition that occurs after a race condition and a NULL pointer dereference.(CVE-2017-15102)

The rtnl_fill_link_ifmap function in net/core/rtnetlink.c in the Linux kernel before 4.5.5 does not initialize a certain data structure, which allows local users to obtain sensitive information from kernel stack memory by reading a Netlink message.(CVE-2016-4486)

A vulnerability was found in the Linux kernel's ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel' package(s) on Huawei EulerOS Virtualization for ARM 64 3.0.1.0.");

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

if(release == "EULEROSVIRTARM64-3.0.1.0") {

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~4.19.28~1.2.117", rls:"EULEROSVIRTARM64-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.19.28~1.2.117", rls:"EULEROSVIRTARM64-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~4.19.28~1.2.117", rls:"EULEROSVIRTARM64-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~4.19.28~1.2.117", rls:"EULEROSVIRTARM64-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~4.19.28~1.2.117", rls:"EULEROSVIRTARM64-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs-devel", rpm:"kernel-tools-libs-devel~4.19.28~1.2.117", rls:"EULEROSVIRTARM64-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~4.19.28~1.2.117", rls:"EULEROSVIRTARM64-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~4.19.28~1.2.117", rls:"EULEROSVIRTARM64-3.0.1.0"))) {
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
