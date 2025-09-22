# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840134");
  script_cve_id("CVE-2006-7203", "CVE-2007-0005", "CVE-2007-1000", "CVE-2007-1353", "CVE-2007-1861", "CVE-2007-2242", "CVE-2007-2453", "CVE-2007-2525", "CVE-2007-2875", "CVE-2007-2876", "CVE-2007-2878");
  script_tag(name:"creation_date", value:"2009-03-23 09:55:18 +0000 (Mon, 23 Mar 2009)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_name("Ubuntu: Security Advisory (USN-486-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU6\.10");

  script_xref(name:"Advisory-ID", value:"USN-486-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-486-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-source-2.6.17' package(s) announced via the USN-486-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The compat_sys_mount function allowed local users to cause a denial of
service when mounting a smbfs filesystem in compatibility mode.
(CVE-2006-7203)

The Omnikey CardMan 4040 driver (cm4040_cs) did not limit the size of
buffers passed to read() and write(). A local attacker could exploit
this to execute arbitrary code with kernel privileges. (CVE-2007-0005)

Due to a variable handling flaw in the ipv6_getsockopt_sticky()
function a local attacker could exploit the getsockopt() calls to
read arbitrary kernel memory. This could disclose sensitive data.
(CVE-2007-1000)

Ilja van Sprundel discovered that Bluetooth setsockopt calls could leak
kernel memory contents via an uninitialized stack buffer. A local
attacker could exploit this flaw to view sensitive kernel information.
(CVE-2007-1353)

A flaw was discovered in the handling of netlink messages. Local
attackers could cause infinite recursion leading to a denial of service.
(CVE-2007-1861)

A flaw was discovered in the IPv6 stack's handling of type 0 route
headers. By sending a specially crafted IPv6 packet, a remote attacker
could cause a denial of service between two IPv6 hosts. (CVE-2007-2242)

The random number generator was hashing a subset of the available
entropy, leading to slightly less random numbers. Additionally, systems
without an entropy source would be seeded with the same inputs at boot
time, leading to a repeatable series of random numbers. (CVE-2007-2453)

A flaw was discovered in the PPP over Ethernet implementation. Local
attackers could manipulate ioctls and cause kernel memory consumption
leading to a denial of service. (CVE-2007-2525)

An integer underflow was discovered in the cpuset filesystem. If mounted,
local attackers could obtain kernel memory using large file offsets
while reading the tasks file. This could disclose sensitive data.
(CVE-2007-2875)

Vilmos Nebehaj discovered that the SCTP netfilter code did not correctly
validate certain states. A remote attacker could send a specially
crafted packet causing a denial of service. (CVE-2007-2876)

Luca Tettamanti discovered a flaw in the VFAT compat ioctls on 64-bit
systems. A local attacker could corrupt a kernel_dirent struct and
cause a denial of service. (CVE-2007-2878)");

  script_tag(name:"affected", value:"'linux-source-2.6.17' package(s) on Ubuntu 6.10.");

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

if(release == "UBUNTU6.10") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.17-12-386", ver:"2.6.17.1-12.39", rls:"UBUNTU6.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.17-12-generic", ver:"2.6.17.1-12.39", rls:"UBUNTU6.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.17-12-hppa32", ver:"2.6.17.1-12.39", rls:"UBUNTU6.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.17-12-hppa64", ver:"2.6.17.1-12.39", rls:"UBUNTU6.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.17-12-itanium", ver:"2.6.17.1-12.39", rls:"UBUNTU6.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.17-12-mckinley", ver:"2.6.17.1-12.39", rls:"UBUNTU6.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.17-12-powerpc", ver:"2.6.17.1-12.39", rls:"UBUNTU6.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.17-12-powerpc-smp", ver:"2.6.17.1-12.39", rls:"UBUNTU6.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.17-12-powerpc64-smp", ver:"2.6.17.1-12.39", rls:"UBUNTU6.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.17-12-server", ver:"2.6.17.1-12.39", rls:"UBUNTU6.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.17-12-server-bigiron", ver:"2.6.17.1-12.39", rls:"UBUNTU6.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.17-12-sparc64", ver:"2.6.17.1-12.39", rls:"UBUNTU6.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.17-12-sparc64-smp", ver:"2.6.17.1-12.39", rls:"UBUNTU6.10"))) {
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
