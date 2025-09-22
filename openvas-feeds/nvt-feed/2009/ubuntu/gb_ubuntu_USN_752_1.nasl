# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63812");
  script_cve_id("CVE-2008-4307", "CVE-2008-6107", "CVE-2009-0028", "CVE-2009-0029", "CVE-2009-0065", "CVE-2009-0322", "CVE-2009-0675", "CVE-2009-0676", "CVE-2009-0834", "CVE-2009-0835", "CVE-2009-0859");
  script_tag(name:"creation_date", value:"2009-04-15 20:11:00 +0000 (Wed, 15 Apr 2009)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-752-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU6\.06\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-752-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-752-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-source-2.6.15' package(s) announced via the USN-752-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"NFS did not correctly handle races between fcntl and interrupts. A local
attacker on an NFS mount could consume unlimited kernel memory, leading to
a denial of service. (CVE-2008-4307)

Sparc syscalls did not correctly check mmap regions. A local attacker could
cause a system panic, leading to a denial of service. (CVE-2008-6107)

In certain situations, cloned processes were able to send signals to parent
processes, crossing privilege boundaries. A local attacker could send
arbitrary signals to parent processes, leading to a denial of service.
(CVE-2009-0028)

The 64-bit syscall interfaces did not correctly handle sign extension. A
local attacker could make malicious syscalls, possibly gaining root
privileges. The x86_64 architecture was not affected. (CVE-2009-0029)

The SCTP stack did not correctly validate FORWARD-TSN packets. A remote
attacker could send specially crafted SCTP traffic causing a system crash,
leading to a denial of service. (CVE-2009-0065)

The Dell platform device did not correctly validate user parameters. A
local attacker could perform specially crafted reads to crash the system,
leading to a denial of service. (CVE-2009-0322)

Network interfaces statistics for the SysKonnect FDDI driver did not check
capabilities. A local user could reset statistics, potentially interfering
with packet accounting systems. (CVE-2009-0675)

The getsockopt function did not correctly clear certain parameters. A local
attacker could read leaked kernel memory, leading to a loss of privacy.
(CVE-2009-0676)

The syscall interface did not correctly validate parameters when crossing
the 64-bit/32-bit boundary. A local attacker could bypass certain syscall
restricts via crafted syscalls. (CVE-2009-0834, CVE-2009-0835)

The shared memory subsystem did not correctly handle certain shmctl calls
when CONFIG_SHMEM was disabled. Ubuntu kernels were not vulnerable, since
CONFIG_SHMEM is enabled by default. (CVE-2009-0859)");

  script_tag(name:"affected", value:"'linux-source-2.6.15' package(s) on Ubuntu 6.06.");

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

if(release == "UBUNTU6.06 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-54-386", ver:"2.6.15-54.76", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-54-686", ver:"2.6.15-54.76", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-54-amd64-generic", ver:"2.6.15-54.76", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-54-amd64-k8", ver:"2.6.15-54.76", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-54-amd64-server", ver:"2.6.15-54.76", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-54-amd64-xeon", ver:"2.6.15-54.76", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-54-hppa32", ver:"2.6.15-54.76", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-54-hppa32-smp", ver:"2.6.15-54.76", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-54-hppa64", ver:"2.6.15-54.76", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-54-hppa64-smp", ver:"2.6.15-54.76", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-54-itanium", ver:"2.6.15-54.76", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-54-itanium-smp", ver:"2.6.15-54.76", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-54-k7", ver:"2.6.15-54.76", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-54-mckinley", ver:"2.6.15-54.76", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-54-mckinley-smp", ver:"2.6.15-54.76", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-54-powerpc", ver:"2.6.15-54.76", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-54-powerpc-smp", ver:"2.6.15-54.76", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-54-powerpc64-smp", ver:"2.6.15-54.76", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-54-server", ver:"2.6.15-54.76", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-54-server-bigiron", ver:"2.6.15-54.76", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-54-sparc64", ver:"2.6.15-54.76", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-54-sparc64-smp", ver:"2.6.15-54.76", rls:"UBUNTU6.06 LTS"))) {
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
