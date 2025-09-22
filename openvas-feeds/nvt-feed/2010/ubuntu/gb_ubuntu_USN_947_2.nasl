# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840441");
  script_cve_id("CVE-2009-4271", "CVE-2009-4537", "CVE-2010-0008", "CVE-2010-0298", "CVE-2010-0306", "CVE-2010-0419", "CVE-2010-0437", "CVE-2010-0727", "CVE-2010-0741", "CVE-2010-1083", "CVE-2010-1084");
  script_tag(name:"creation_date", value:"2010-06-07 13:46:00 +0000 (Mon, 07 Jun 2010)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_name("Ubuntu: Security Advisory (USN-947-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU10\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-947-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-947-2");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/589163");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux' package(s) announced via the USN-947-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-947-1 fixed vulnerabilities in the Linux kernel. Fixes for
CVE-2010-0419 caused failures when using KVM in certain situations.
This update reverts that fix until a better solution can be found.

We apologize for the inconvenience.

Original advisory details:

 It was discovered that the Linux kernel did not correctly handle memory
 protection of the Virtual Dynamic Shared Object page when running
 a 32-bit application on a 64-bit kernel. A local attacker could
 exploit this to cause a denial of service. (Only affected Ubuntu 6.06
 LTS.) (CVE-2009-4271)

 It was discovered that the r8169 network driver did not correctly check
 the size of Ethernet frames. A remote attacker could send specially
 crafted traffic to crash the system, leading to a denial of service.
 (CVE-2009-4537)

 Wei Yongjun discovered that SCTP did not correctly validate certain
 chunks. A remote attacker could send specially crafted traffic to
 monopolize CPU resources, leading to a denial of service. (Only affected
 Ubuntu 6.06 LTS.) (CVE-2010-0008)

 It was discovered that KVM did not correctly limit certain privileged
 IO accesses on x86. Processes in the guest OS with access to IO regions
 could gain further privileges within the guest OS. (Did not affect Ubuntu
 6.06 LTS.) (CVE-2010-0298, CVE-2010-0306, CVE-2010-0419)

 Evgeniy Polyakov discovered that IPv6 did not correctly handle
 certain TUN packets. A remote attacker could exploit this to crash
 the system, leading to a denial of service. (Only affected Ubuntu 8.04
 LTS.) (CVE-2010-0437)

 Sachin Prabhu discovered that GFS2 did not correctly handle certain locks.
 A local attacker with write access to a GFS2 filesystem could exploit
 this to crash the system, leading to a denial of service. (CVE-2010-0727)

 Jamie Strandboge discovered that network virtio in KVM did not correctly
 handle certain high-traffic conditions. A remote attacker could exploit
 this by sending specially crafted traffic to a guest OS, causing the
 guest to crash, leading to a denial of service. (Only affected Ubuntu
 8.04 LTS.) (CVE-2010-0741)

 Marcus Meissner discovered that the USB subsystem did not correctly handle
 certain error conditions. A local attacker with access to a USB device
 could exploit this to read recently used kernel memory, leading to a
 loss of privacy and potentially root privilege escalation. (CVE-2010-1083)

 Neil Brown discovered that the Bluetooth subsystem did not correctly
 handle large amounts of traffic. A physically proximate remote attacker
 could exploit this by sending specially crafted traffic that would consume
 all available system memory, leading to a denial of service. (Ubuntu
 6.06 LTS and 10.04 LTS were not affected.) (CVE-2010-1084)

 Jody Bruchon discovered that the sound driver for the AMD780V did not
 correctly handle certain conditions. A local attacker with access to
 this hardware could exploit the flaw to cause a ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.32-22-386", ver:"2.6.32-22.36", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.32-22-generic", ver:"2.6.32-22.36", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.32-22-generic-pae", ver:"2.6.32-22.36", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.32-22-lpia", ver:"2.6.32-22.36", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.32-22-preempt", ver:"2.6.32-22.36", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.32-22-server", ver:"2.6.32-22.36", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.32-22-virtual", ver:"2.6.32-22.36", rls:"UBUNTU10.04 LTS"))) {
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
