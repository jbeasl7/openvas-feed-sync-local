# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841404");
  script_cve_id("CVE-2012-6542", "CVE-2012-6544", "CVE-2012-6545", "CVE-2012-6546", "CVE-2012-6548", "CVE-2013-0228", "CVE-2013-0349", "CVE-2013-1774", "CVE-2013-1796");
  script_tag(name:"creation_date", value:"2013-04-22 05:03:11 +0000 (Mon, 22 Apr 2013)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:H/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-1805-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU10\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-1805-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1805-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux' package(s) announced via the USN-1805-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Mathias Krause discovered an information leak in the Linux kernel's
getsockname implementation for Logical Link Layer (llc) sockets. A local
user could exploit this flaw to examine some of the kernel's stack memory.
(CVE-2012-6542)

Mathias Krause discovered information leaks in the Linux kernel's Bluetooth
Logical Link Control and Adaptation Protocol (L2CAP) implementation. A
local user could exploit these flaws to examine some of the kernel's stack
memory. (CVE-2012-6544)

Mathias Krause discovered information leaks in the Linux kernel's Bluetooth
RFCOMM protocol implementation. A local user could exploit these flaws to
examine parts of kernel memory. (CVE-2012-6545)

Mathias Krause discovered information leaks in the Linux kernel's
Asynchronous Transfer Mode (ATM) networking stack. A local user could
exploit these flaws to examine some parts of kernel memory. (CVE-2012-6546)

Mathias Krause discovered an information leak in the Linux kernel's UDF
file system implementation. A local user could exploit this flaw to examine
some of the kernel's heap memory. (CVE-2012-6548)

Andrew Jones discovered a flaw with the xen_iret function in Linux kernel's
Xen virtualizeation. In the 32-bit Xen paravirt platform an unprivileged
guest OS user could exploit this flaw to cause a denial of service (crash
the system) or gain guest OS privilege. (CVE-2013-0228)

An information leak was discovered in the Linux kernel's Bluetooth stack
when HIDP (Human Interface Device Protocol) support is enabled. A local
unprivileged user could exploit this flaw to cause an information leak from
the kernel. (CVE-2013-0349)

A flaw was discovered in the Edgeort USB serial converter driver when the
device is disconnected while it is in use. A local user could exploit this
flaw to cause a denial of service (system crash). (CVE-2013-1774)

Andrew Honig discovered a flaw in guest OS time updates in the Linux
kernel's KVM (Kernel-based Virtual Machine). A privileged guest user could
exploit this flaw to cause a denial of service (crash host system) or
potential escalate privilege to the host kernel level. (CVE-2013-1796)");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.32-46-386", ver:"2.6.32-46.108", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.32-46-generic", ver:"2.6.32-46.108", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.32-46-generic-pae", ver:"2.6.32-46.108", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.32-46-ia64", ver:"2.6.32-46.108", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.32-46-lpia", ver:"2.6.32-46.108", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.32-46-powerpc", ver:"2.6.32-46.108", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.32-46-powerpc-smp", ver:"2.6.32-46.108", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.32-46-powerpc64-smp", ver:"2.6.32-46.108", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.32-46-preempt", ver:"2.6.32-46.108", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.32-46-server", ver:"2.6.32-46.108", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.32-46-sparc64", ver:"2.6.32-46.108", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.32-46-sparc64-smp", ver:"2.6.32-46.108", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.32-46-versatile", ver:"2.6.32-46.108", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.32-46-virtual", ver:"2.6.32-46.108", rls:"UBUNTU10.04 LTS"))) {
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
