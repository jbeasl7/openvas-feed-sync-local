# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840592");
  script_cve_id("CVE-2010-0435", "CVE-2010-3448", "CVE-2010-3698", "CVE-2010-3859", "CVE-2010-3865", "CVE-2010-3873", "CVE-2010-3874", "CVE-2010-3875", "CVE-2010-3876", "CVE-2010-3877", "CVE-2010-3880", "CVE-2010-4073", "CVE-2010-4074", "CVE-2010-4078", "CVE-2010-4079", "CVE-2010-4080", "CVE-2010-4081", "CVE-2010-4082", "CVE-2010-4083", "CVE-2010-4157", "CVE-2010-4160", "CVE-2010-4165", "CVE-2010-4169", "CVE-2010-4248", "CVE-2010-4249");
  script_tag(name:"creation_date", value:"2011-02-28 15:24:14 +0000 (Mon, 28 Feb 2011)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-1073-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU9\.10");

  script_xref(name:"Advisory-ID", value:"USN-1073-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1073-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-ec2' package(s) announced via the USN-1073-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Gleb Napatov discovered that KVM did not correctly check certain privileged
operations. A local attacker with access to a guest kernel could exploit
this to crash the host system, leading to a denial of service.
(CVE-2010-0435)

Dan Jacobson discovered that ThinkPad video output was not correctly access
controlled. A local attacker could exploit this to hang the system, leading
to a denial of service. (CVE-2010-3448)

It was discovered that KVM did not correctly initialize certain CPU
registers. A local attacker could exploit this to crash the system, leading
to a denial of service. (CVE-2010-3698)

Dan Rosenberg discovered that the Linux kernel TIPC implementation
contained multiple integer signedness errors. A local attacker could
exploit this to gain root privileges. (CVE-2010-3859)

Thomas Pollet discovered that the RDS network protocol did not
check certain iovec buffers. A local attacker could exploit this
to crash the system or possibly execute arbitrary code as the root
user. (CVE-2010-3865)

Dan Rosenberg discovered that the Linux kernel X.25 implementation
incorrectly parsed facilities. A remote attacker could exploit this to
crash the kernel, leading to a denial of service. (CVE-2010-3873)

Dan Rosenberg discovered that the CAN protocol on 64bit systems did not
correctly calculate the size of certain buffers. A local attacker could
exploit this to crash the system or possibly execute arbitrary code as
the root user. (CVE-2010-3874)

Vasiliy Kulikov discovered that the Linux kernel X.25 implementation did
not correctly clear kernel memory. A local attacker could exploit this to
read kernel stack memory, leading to a loss of privacy. (CVE-2010-3875)

Vasiliy Kulikov discovered that the Linux kernel sockets implementation did
not properly initialize certain structures. A local attacker could exploit
this to read kernel stack memory, leading to a loss of privacy.
(CVE-2010-3876)

Vasiliy Kulikov discovered that the TIPC interface did not correctly
initialize certain structures. A local attacker could exploit this to read
kernel stack memory, leading to a loss of privacy. (CVE-2010-3877)

Nelson Elhage discovered that the Linux kernel IPv4 implementation did not
properly audit certain bytecodes in netlink messages. A local attacker
could exploit this to cause the kernel to hang, leading to a denial of
service. (CVE-2010-3880)

Dan Rosenberg discovered that IPC structures were not correctly initialized
on 64bit systems. A local attacker could exploit this to read kernel stack
memory, leading to a loss of privacy. (CVE-2010-4073)

Dan Rosenberg discovered that the USB subsystem did not correctly
initialize certain structures. A local attacker could exploit this to read
kernel stack memory, leading to a loss of privacy. (CVE-2010-4074)

Dan Rosenberg discovered that the SiS video driver did not correctly clear
kernel memory. A local attacker could exploit this to read ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux, linux-ec2' package(s) on Ubuntu 9.10.");

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

if(release == "UBUNTU9.10") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.31-22-386", ver:"2.6.31-22.73", rls:"UBUNTU9.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.31-22-generic", ver:"2.6.31-22.73", rls:"UBUNTU9.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.31-22-generic-pae", ver:"2.6.31-22.73", rls:"UBUNTU9.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.31-22-ia64", ver:"2.6.31-22.73", rls:"UBUNTU9.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.31-22-lpia", ver:"2.6.31-22.73", rls:"UBUNTU9.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.31-22-powerpc", ver:"2.6.31-22.73", rls:"UBUNTU9.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.31-22-powerpc-smp", ver:"2.6.31-22.73", rls:"UBUNTU9.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.31-22-powerpc64-smp", ver:"2.6.31-22.73", rls:"UBUNTU9.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.31-22-server", ver:"2.6.31-22.73", rls:"UBUNTU9.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.31-22-sparc64", ver:"2.6.31-22.73", rls:"UBUNTU9.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.31-22-sparc64-smp", ver:"2.6.31-22.73", rls:"UBUNTU9.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.31-22-virtual", ver:"2.6.31-22.73", rls:"UBUNTU9.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.31-307-ec2", ver:"2.6.31-307.27", rls:"UBUNTU9.10"))) {
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
