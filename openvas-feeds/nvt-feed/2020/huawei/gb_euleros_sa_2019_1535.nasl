# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2019.1535");
  script_cve_id("CVE-2013-2929", "CVE-2013-6382", "CVE-2013-7271", "CVE-2013-7348", "CVE-2014-1738", "CVE-2014-8172", "CVE-2015-4167", "CVE-2015-4177", "CVE-2015-4692", "CVE-2016-1583", "CVE-2016-2064", "CVE-2016-3140", "CVE-2016-5829", "CVE-2016-7912", "CVE-2016-9793", "CVE-2017-16645", "CVE-2017-7487", "CVE-2017-9986", "CVE-2018-5333", "CVE-2019-9857");
  script_tag(name:"creation_date", value:"2020-01-23 12:07:51 +0000 (Thu, 23 Jan 2020)");
  script_version("2024-02-05T14:36:56+0000");
  script_tag(name:"last_modification", value:"2024-02-05 14:36:56 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-06-30 18:19:54 +0000 (Fri, 30 Jun 2017)");

  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2019-1535)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRTARM64\-3\.0\.1\.0");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2019-1535");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2019-1535");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'kernel' package(s) announced via the EulerOS-SA-2019-1535 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The ims_pcu_get_cdc_union_desc function in drivers/input/misc/ims-pcu.c in the Linux kernel, through 4.13.11, allows local users to cause a denial of service (ims_pcu_parse_cdc_data out-of-bounds read and system crash) or possibly have unspecified other impact via a crafted USB device.(CVE-2017-16645)

It was found that due to excessive files_lock locking, a soft lockup could be triggered in the Linux kernel when performing asynchronous I/O operations. A local, unprivileged user could use this flaw to crash the system.(CVE-2014-8172)

A flaw was discovered in the kernel's collect_mounts function. If the kernel's audit subsystem called collect_mounts to audit an unmounted path, it could panic the system. With this flaw, an unprivileged user could call umount(MNT_DETACH) to launch a denial-of-service attack.(CVE-2015-4177)

A flaw was found in the way the Linux kernel's floppy driver handled user space provided data in certain error code paths while processing FDRAWCMD IOCTL commands. A local user with write access to /dev/fdX could use this flaw to free (using the kfree() function) arbitrary kernel memory. (CVE-2014-1737, Important) was found that the Linux kernel's floppy driver leaked internal kernel memory addresses to user space during the processing of the FDRAWCMD IOCTL command. A local user with write access to /dev/fdX could use this flaw to obtain information about the kernel heap arrangement. (CVE-2014-1738, Low)Note: A local user with write access to /dev/fdX could use these two flaws (CVE-2014-1737 in combination with CVE-2014-1738) to escalate their privileges on the system.(CVE-2014-1738)

A reference counter leak in Linux kernel in ipxitf_ioctl function was found which results in a use after free vulnerability that's triggerable from unprivileged userspace when IPX interface is configured.(CVE-2017-7487)

The x25_recvmsg function in net/x25/af_x25.c in the Linux kernel before 3.12.4 updates a certain length value without ensuring that an associated data structure has been initialized, which allows local users to obtain sensitive information from kernel memory via a (1) recvfrom, (2) recvmmsg, or (3) recvmsg system call.(CVE-2013-7271)

An inode data validation error was found in Linux kernels built with UDF file system (CONFIG_UDF_FS) support. An attacker able to mount a corrupted/malicious UDF file system image could cause the kernel to crash.(CVE-2015-4167)

Double free vulnerability in the ioctx_alloc function in fs/aio.c in the Linux kernel before 3.12.4 allows local users to cause a denial of service (system crash) or possibly have unspecified other impact via vectors involving an error condition in the aio_setup_ring function.(CVE-2013-7348)

A flaw was found in the Linux kernel's implementation of setsockopt for the SO_{SND<pipe>RCV}BUFFORCE setsockopt() system call. Users with non-namespace CAP_NET_ADMIN are able to trigger this call and create a ... [Please see the references for more information on the vulnerabilities]");

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
