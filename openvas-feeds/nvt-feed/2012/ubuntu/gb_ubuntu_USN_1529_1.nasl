# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841104");
  script_cve_id("CVE-2012-2119", "CVE-2012-2136", "CVE-2012-2137", "CVE-2012-2372", "CVE-2012-2373", "CVE-2012-2669", "CVE-2012-3364", "CVE-2012-3375", "CVE-2012-3400", "CVE-2012-3511", "CVE-2012-6638");
  script_tag(name:"creation_date", value:"2012-08-14 05:10:22 +0000 (Tue, 14 Aug 2012)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_name("Ubuntu: Security Advisory (USN-1529-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU12\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-1529-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1529-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux' package(s) announced via the USN-1529-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A flaw was discovered in the Linux kernel's macvtap device driver, which is
used in KVM (Kernel-based Virtual Machine) to create a network bridge
between host and guest. A privleged user in a guest could exploit this flaw
to crash the host, if the vhost_net module is loaded with the
experimental_zcopytx option enabled. (CVE-2012-2119)

An error was discovered in the Linux kernel's network TUN/TAP device
implementation. A local user with access to the TUN/TAP interface (which is
not available to unprivileged users until granted by a root user) could
exploit this flaw to crash the system or potential gain administrative
privileges. (CVE-2012-2136)

A flaw was found in how the Linux kernel's KVM (Kernel-based Virtual
Machine) subsystem handled MSI (Message Signaled Interrupts). A local
unprivileged user could exploit this flaw to cause a denial of service or
potentially elevate privileges. (CVE-2012-2137)

A flaw was found in the Linux kernel's Reliable Datagram Sockets (RDS)
protocol implementation. A local, unprivileged user could use this flaw to
cause a denial of service. (CVE-2012-2372)

Ulrich Obergfell discovered an error in the Linux kernel's memory
management subsystem on 32 bit PAE systems with more than 4GB of memory
installed. A local unprivileged user could exploit this flaw to crash the
system. (CVE-2012-2373)

It was discovered that hypervkvpd, which is distributed in the Linux
kernel, was not correctly validating the origin on Netlink messages. An
untrusted local user can cause a denial of service of Linux guests in
Hyper-V virtualization environments. (CVE-2012-2669)

Dan Rosenberg discovered flaws in the Linux kernel's NCI (Near Field
Communication Controller Interface). A remote attacker could exploit these
flaws to crash the system or potentially execute privileged code.
(CVE-2012-3364)

A flaw was discovered in the Linux kernel's epoll system call. An
unprivileged local user could use this flaw to crash the system.
(CVE-2012-3375)

Some errors where discovered in the Linux kernel's UDF file system, which
is used to mount some CD-ROMs and DVDs. An unprivileged local user could
use these flaws to crash the system. (CVE-2012-3400)

A flaw was discovered in the madvise feature of the Linux kernel's memory
subsystem. An unprivileged local use could exploit the flaw to cause a
denial of service (crash the system). (CVE-2012-3511)

Denys Fedoryshchenko discovered a flaw in the Linux kernel's TCP receive
processing for IPv4. A remote attacker could exploit this flaw to cause a
denial of service (kernel resource consumption) via a flood of SYN+FIN TCP
packets. (CVE-2012-6638)");

  script_tag(name:"affected", value:"'linux' package(s) on Ubuntu 12.04.");

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

if(release == "UBUNTU12.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-29-generic", ver:"3.2.0-29.46", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-29-generic-pae", ver:"3.2.0-29.46", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-29-highbank", ver:"3.2.0-29.46", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-29-omap", ver:"3.2.0-29.46", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-29-powerpc-smp", ver:"3.2.0-29.46", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-29-powerpc64-smp", ver:"3.2.0-29.46", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-29-virtual", ver:"3.2.0-29.46", rls:"UBUNTU12.04 LTS"))) {
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
