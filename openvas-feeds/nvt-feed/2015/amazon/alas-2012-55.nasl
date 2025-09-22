# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.120412");
  script_cve_id("CVE-2011-4077", "CVE-2011-4081", "CVE-2011-4132", "CVE-2011-4347", "CVE-2011-4594", "CVE-2011-4611", "CVE-2011-4622", "CVE-2012-0038", "CVE-2012-0045", "CVE-2012-0207");
  script_tag(name:"creation_date", value:"2015-09-08 11:25:46 +0000 (Tue, 08 Sep 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-07-30 19:39:00 +0000 (Thu, 30 Jul 2020)");

  script_name("Amazon Linux: Security Advisory (ALAS-2012-55)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Amazon Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/amazon_linux", "ssh/login/release");

  script_xref(name:"Advisory-ID", value:"ALAS-2012-55");
  script_xref(name:"URL", value:"https://alas.aws.amazon.com/ALAS-2012-55.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel' package(s) announced via the ALAS-2012-55 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A buffer overflow flaw was found in the way the Linux kernel's XFS file system implementation handled links with overly long path names. A local, unprivileged user could use this flaw to cause a denial of service or escalate their privileges by mounting a specially-crafted disk. (CVE-2011-4077, Moderate)

Flaws in ghash_update() and ghash_final() could allow a local, unprivileged user to cause a denial of service. (CVE-2011-4081, Moderate)

A flaw was found in the Linux kernel's Journaling Block Device (JBD). A local, unprivileged user could use this flaw to crash the system by mounting a specially-crafted ext3 or ext4 disk. (CVE-2011-4132, Moderate)

It was found that the kvm_vm_ioctl_assign_device() function in the KVM (Kernel-based Virtual Machine) subsystem of a Linux kernel did not check if the user requesting device assignment was privileged or not. A local, unprivileged user on the host could assign unused PCI devices, or even devices that were in use and whose resources were not properly claimed by the respective drivers, which could result in the host crashing. (CVE-2011-4347, Moderate)

Two flaws were found in the way the Linux kernel's __sys_sendmsg() function, when invoked via the sendmmsg() system call, accessed user-space memory. A local, unprivileged user could use these flaws to cause a denial of service. (CVE-2011-4594, Moderate)

A previous update introduced an integer overflow flaw in the Linux kernel. On PowerPC systems, a local, unprivileged user could use this flaw to cause a denial of service. (CVE-2011-4611, Moderate)

A flaw was found in the way the KVM subsystem of a Linux kernel handled PIT (Programmable Interval Timer) IRQs (interrupt requests) when there was no virtual interrupt controller set up. A local, unprivileged user on the host could force this situation to occur, resulting in the host crashing. (CVE-2011-4622, Moderate)

A flaw was found in the way the Linux kernel's XFS file system implementation handled on-disk Access Control Lists (ACLs). A local, unprivileged user could use this flaw to cause a denial of service or escalate their privileges by mounting a specially-crafted disk. (CVE-2012-0038, Moderate)

A flaw was found in the way the Linux kernel's KVM hypervisor implementation emulated the syscall instruction for 32-bit guests. An unprivileged guest user could trigger this flaw to crash the guest. (CVE-2012-0045, Moderate)

A divide-by-zero flaw was found in the Linux kernel's igmp_heard_query() function. An attacker able to send certain IGMP (Internet Group Management Protocol) packets to a target system could use this flaw to cause a denial of service. (CVE-2012-0207, Moderate)");

  script_tag(name:"affected", value:"'kernel' package(s) on Amazon Linux.");

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

if(release == "AMAZON") {

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.35.14~107.1.39.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debuginfo", rpm:"kernel-debuginfo~2.6.35.14~107.1.39.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debuginfo-common-i686", rpm:"kernel-debuginfo-common-i686~2.6.35.14~107.1.39.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debuginfo-common-x86_64", rpm:"kernel-debuginfo-common-x86_64~2.6.35.14~107.1.39.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.35.14~107.1.39.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.35.14~107.1.39.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.35.14~107.1.39.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~2.6.35.14~107.1.39.amzn1", rls:"AMAZON"))) {
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
