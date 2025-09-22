# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2019.1526");
  script_cve_id("CVE-2010-5321", "CVE-2013-2896", "CVE-2013-6432", "CVE-2013-7027", "CVE-2013-7270", "CVE-2014-3645", "CVE-2014-3687", "CVE-2014-9710", "CVE-2016-2053", "CVE-2016-2062", "CVE-2016-3139", "CVE-2016-9806", "CVE-2017-10662", "CVE-2017-10810", "CVE-2017-17053", "CVE-2017-18208", "CVE-2017-7542", "CVE-2018-1108", "CVE-2018-17182", "CVE-2019-7222");
  script_tag(name:"creation_date", value:"2020-01-23 12:04:52 +0000 (Thu, 23 Jan 2020)");
  script_version("2024-02-05T14:36:56+0000");
  script_tag(name:"last_modification", value:"2024-02-05 14:36:56 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-11-28 14:25:09 +0000 (Wed, 28 Nov 2018)");

  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2019-1526)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRTARM64\-3\.0\.1\.0");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2019-1526");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2019-1526");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'kernel' package(s) announced via the EulerOS-SA-2019-1526 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A double free vulnerability was found in netlink_dump, which could cause a denial of service or possibly other unspecified impact. Due to the nature of the flaw, privilege escalation cannot be fully ruled out, although we believe it is unlikely.(CVE-2016-9806)

Memory leak in drivers/media/video/videobuf-core.c in the videobuf subsystem in the Linux kernel 2.6.x through 4.x allows local users to cause a denial of service (memory consumption) by leveraging /dev/video access for a series of mmap calls that require new allocations, a different vulnerability than CVE-2007-6761. NOTE: as of 2016-06-18, this affects only 11 drivers that have not been updated to use videobuf2 instead of videobuf.(CVE-2010-5321)

** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.(CVE-2018-1108)

The KVM implementation in the Linux kernel through 4.20.5 has an Information Leak.(CVE-2019-7222)

The adreno_perfcounter_query_group function in drivers/gpu/msm/adreno_perfcounter.c in the Adreno GPU driver for the Linux kernel 3.x, as used in Qualcomm Innovation Center (QuIC) Android contributions for MSM devices and other products, uses an incorrect integer data type, which allows attackers to cause a denial of service (integer overflow, heap-based buffer overflow, and incorrect memory allocation) or possibly have unspecified other impact via a crafted IOCTL_KGSL_PERFCOUNTER_QUERY ioctl call.(CVE-2016-2062)

drivers/hid/hid-ntrig.c in the Human Interface Device (HID) subsystem in the Linux kernel through 3.11, when CONFIG_HID_NTRIG is enabled, allows physically proximate attackers to cause a denial of service (NULL pointer dereference and OOPS) via a crafted device.(CVE-2013-2896)

The wacom_probe function in drivers/input/tablet/wacom_sys.c in the Linux kernel before 3.17 allows physically proximate attackers to cause a denial of service (NULL pointer dereference and system crash) via a crafted endpoints value in a USB device descriptor.(CVE-2016-3139)

An integer overflow vulnerability in ip6_find_1stfragopt() function was found. A local attacker that has privileges (of CAP_NET_RAW) to open raw socket can cause an infinite loop inside the ip6_find_1stfragopt() function.(CVE-2017-7542)

Memory leak in the virtio_gpu_object_create function in drivers/gpu/drm/virtio/virtgpu_object.c in the Linux kernel through 4.11.8 allows attackers to cause a denial of service (memory consumption) by triggering object-initialization failures.(CVE-2017-10810)

The ping_recvmsg function in net/ipv4/ping.c in the Linux kernel before 3.12.4 does not properly interact with read system calls on ping sockets, which allows local users to cause a denial of service (NULL pointer dereference and system crash) by leveraging unspecified privileges to ... [Please see the references for more information on the vulnerabilities]");

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
