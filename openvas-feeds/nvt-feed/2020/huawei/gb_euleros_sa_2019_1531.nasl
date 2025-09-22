# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2019.1531");
  script_cve_id("CVE-2013-4343", "CVE-2013-4511", "CVE-2014-4171", "CVE-2014-5077", "CVE-2015-5156", "CVE-2015-6252", "CVE-2016-2068", "CVE-2016-7042", "CVE-2016-9919", "CVE-2017-12190", "CVE-2017-18224", "CVE-2017-7277", "CVE-2017-7477", "CVE-2017-9075", "CVE-2018-1095", "CVE-2018-13405", "CVE-2018-18397", "CVE-2018-19854", "CVE-2018-6412", "CVE-2019-6974");
  script_tag(name:"creation_date", value:"2020-01-23 12:06:32 +0000 (Thu, 23 Jan 2020)");
  script_version("2024-02-05T14:36:56+0000");
  script_tag(name:"last_modification", value:"2024-02-05 14:36:56 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-05 20:40:45 +0000 (Tue, 05 Apr 2022)");

  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2019-1531)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRTARM64\-3\.0\.1\.0");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2019-1531");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2019-1531");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'kernel' package(s) announced via the EulerOS-SA-2019-1531 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Use-after-free vulnerability in drivers
et/tun.c in the Linux kernel through 3.11.1 allows local users to gain privileges by leveraging the CAP_NET_ADMIN capability and providing an invalid tuntap interface name in a TUNSETIFF ioctl call.(CVE-2013-4343)

It was found that when the gcc stack protector was enabled, reading the /proc/keys file could cause a panic in the Linux kernel due to stack corruption. This happened because an incorrect buffer size was used to hold a 64-bit timeout value rendered as weeks.(CVE-2016-7042)

A flaw was found in the Linux kernel that fs/ocfs2/aops.c omits use of a semaphore and consequently has a race condition for access to the extent tree during read operations in DIRECT mode. This allows local users to cause a denial of service by modifying a certain e_cpos field.(CVE-2017-18224)

The sctp_v6_create_accept_sk function in net/sctp/ipv6.c in the Linux kernel mishandles inheritance, which allows local users to cause a denial of service or possibly have unspecified other impact via crafted system calls, a related issue to CVE-2017-8890. An unprivileged local user could use this flaw to induce kernel memory corruption on the system, leading to a crash. Due to the nature of the flaw, privilege escalation cannot be fully ruled out, although we believe it is unlikely.(CVE-2017-9075)

In the function sbusfb_ioctl_helper() in drivers/video/fbdev/sbuslib.c in the Linux kernel, up to and including 4.15, an integer signedness error allows arbitrary information leakage for the FBIOPUTCMAP_SPARC and FBIOGETCMAP_SPARC commands.(CVE-2018-6412)

A race condition flaw was found in the way the Linux kernel's mmap(2), madvise(2), and fallocate(2) system calls interacted with each other while operating on virtual memory file system files. A local user could use this flaw to cause a denial of service.(CVE-2014-4171)

** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.(CVE-2018-1095)

A NULL pointer dereference flaw was found in the way the Linux kernel's Stream Control Transmission Protocol (SCTP) implementation handled simultaneous connections between the same hosts. A remote attacker could use this flaw to crash the system.(CVE-2014-5077)

A vulnerability was found in the fs/inode.c:inode_init_owner() function logic of the LInux kernel that allows local users to create files with an unintended group ownership and with group execution and SGID permission bits set, in a scenario where a directory is SGID and belongs to a certain group and is writable by a user who is not a member of this group. This can lead to excessive permissions granted in case when they should not.(CVE-2018-13405)

In the Linux kernel before 4.20.8, kvm_ioctl_create_device in virt/kvm/kvm_main.c mishandles reference ... [Please see the references for more information on the vulnerabilities]");

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
