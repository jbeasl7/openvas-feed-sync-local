# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841747");
  script_cve_id("CVE-2013-0160", "CVE-2013-2929", "CVE-2013-4587", "CVE-2013-6367", "CVE-2013-6380", "CVE-2013-6382", "CVE-2013-7027", "CVE-2013-7266", "CVE-2013-7267", "CVE-2013-7268", "CVE-2013-7269", "CVE-2013-7270", "CVE-2013-7271", "CVE-2014-1444", "CVE-2014-1445", "CVE-2014-1446", "CVE-2014-1874");
  script_tag(name:"creation_date", value:"2014-03-12 04:11:18 +0000 (Wed, 12 Mar 2014)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-2128-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU10\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-2128-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2128-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux' package(s) announced via the USN-2128-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An information leak was discovered in the Linux kernel when inotify is used
to monitor the /dev/ptmx device. A local user could exploit this flaw to
discover keystroke timing and potentially discover sensitive information
like password length. (CVE-2013-0160)

Vasily Kulikov reported a flaw in the Linux kernel's implementation of
ptrace. An unprivileged local user could exploit this flaw to obtain
sensitive information from kernel memory. (CVE-2013-2929)

Andrew Honig reported a flaw in the Linux Kernel's kvm_vm_ioctl_create_vcpu
function of the Kernel Virtual Machine (KVM) subsystem. A local user could
exploit this flaw to gain privileges on the host machine. (CVE-2013-4587)

Andrew Honig reported a flaw in the apic_get_tmcct function of the Kernel
Virtual Machine (KVM) subsystem if the Linux kernel. A guest OS user could
exploit this flaw to cause a denial of service or host OS system crash.
(CVE-2013-6367)

Nico Golde and Fabian Yamaguchi reported a flaw in the driver for Adaptec
AACRAID scsi raid devices in the Linux kernel. A local user could use this
flaw to cause a denial of service or possibly other unspecified impact.
(CVE-2013-6380)

Nico Golde and Fabian Yamaguchi reported buffer underflow errors in the
implementation of the XFS filesystem in the Linux kernel. A local user with
CAP_SYS_ADMIN could exploit this flaw to cause a denial of service (memory
corruption) or possibly other unspecified issues. (CVE-2013-6382)

Evan Huus reported a buffer overflow in the Linux kernel's radiotap header
parsing. A remote attacker could cause a denial of service (buffer over-
read) via a specially crafted header. (CVE-2013-7027)

An information leak was discovered in the recvfrom, recvmmsg, and recvmsg
systemcalls when used with ISDN sockets in the Linux kernel. A local user
could exploit this leak to obtain potentially sensitive information from
kernel memory. (CVE-2013-7266)

An information leak was discovered in the recvfrom, recvmmsg, and recvmsg
systemcalls when used with apple talk sockets in the Linux kernel. A local
user could exploit this leak to obtain potentially sensitive information
from kernel memory. (CVE-2013-7267)

An information leak was discovered in the recvfrom, recvmmsg, and recvmsg
systemcalls when used with ipx protocol sockets in the Linux kernel. A
local user could exploit this leak to obtain potentially sensitive
information from kernel memory. (CVE-2013-7268)

An information leak was discovered in the recvfrom, recvmmsg, and recvmsg
systemcalls when used with the netrom address family in the Linux kernel. A
local user could exploit this leak to obtain potentially sensitive
information from kernel memory. (CVE-2013-7269)

An information leak was discovered in the recvfrom, recvmmsg, and recvmsg
systemcalls when used with packet address family sockets in the Linux
kernel. A local user could exploit this leak to obtain potentially
sensitive ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux' package(s) on Ubuntu 10.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "UBUNTU10.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.32-57-386", ver:"2.6.32-57.119", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.32-57-generic", ver:"2.6.32-57.119", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.32-57-generic-pae", ver:"2.6.32-57.119", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.32-57-ia64", ver:"2.6.32-57.119", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.32-57-lpia", ver:"2.6.32-57.119", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.32-57-powerpc", ver:"2.6.32-57.119", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.32-57-powerpc-smp", ver:"2.6.32-57.119", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.32-57-powerpc64-smp", ver:"2.6.32-57.119", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.32-57-preempt", ver:"2.6.32-57.119", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.32-57-server", ver:"2.6.32-57.119", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.32-57-sparc64", ver:"2.6.32-57.119", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.32-57-sparc64-smp", ver:"2.6.32-57.119", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.32-57-versatile", ver:"2.6.32-57.119", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.32-57-virtual", ver:"2.6.32-57.119", rls:"UBUNTU10.04 LTS"))) {
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
