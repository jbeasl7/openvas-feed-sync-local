# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840049");
  script_cve_id("CVE-2007-1357", "CVE-2007-1388", "CVE-2007-1496", "CVE-2007-1497", "CVE-2007-1592", "CVE-2007-1730", "CVE-2007-2172");
  script_tag(name:"creation_date", value:"2009-03-23 09:55:18 +0000 (Mon, 23 Mar 2009)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_name("Ubuntu: Security Advisory (USN-464-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(6\.06\ LTS|6\.10|7\.04)");

  script_xref(name:"Advisory-ID", value:"USN-464-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-464-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-source-2.6.15, linux-source-2.6.17, linux-source-2.6.20' package(s) announced via the USN-464-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Philipp Richter discovered that the AppleTalk protocol handler did
not sufficiently verify the length of packets. By sending a crafted
AppleTalk packet, a remote attacker could exploit this to crash the
kernel. (CVE-2007-1357)

Gabriel Campana discovered that the do_ipv6_setsockopt() function did
not sufficiently verify option values for IPV6_RTHDR. A local
attacker could exploit this to trigger a kernel crash. (CVE-2007-1388)

A Denial of Service vulnerability was discovered in the
nfnetlink_log() netfilter function. A remote attacker could exploit
this to trigger a kernel crash. (CVE-2007-1496)

The connection tracking module for IPv6 did not properly handle the
status field when reassembling fragmented packets, so that the final
packet always had the 'established' state. A remote attacker could
exploit this to bypass intended firewall rules. (CVE-2007-1497)

Masayuki Nakagawa discovered an error in the flowlabel handling of
IPv6 network sockets. A local attacker could exploit this to crash
the kernel. (CVE-2007-1592)

The do_dccp_getsockopt() function did not sufficiently verify the
optlen argument. A local attacker could exploit this to read kernel
memory (which might expose sensitive data) or cause a kernel crash.
This only affects Ubuntu 7.04. (CVE-2007-1730)

The IPv4 and DECnet network protocol handlers incorrectly declared
an array variable so that it became smaller than intended. By sending
crafted packets over a netlink socket, a local attacker could exploit
this to crash the kernel. (CVE-2007-2172)");

  script_tag(name:"affected", value:"'linux-source-2.6.15, linux-source-2.6.17, linux-source-2.6.20' package(s) on Ubuntu 6.06, Ubuntu 6.10, Ubuntu 7.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-28-386", ver:"2.6.15-28.55", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-28-686", ver:"2.6.15-28.55", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-28-amd64-generic", ver:"2.6.15-28.55", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-28-amd64-k8", ver:"2.6.15-28.55", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-28-amd64-server", ver:"2.6.15-28.55", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-28-amd64-xeon", ver:"2.6.15-28.55", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-28-hppa32", ver:"2.6.15-28.55", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-28-hppa32-smp", ver:"2.6.15-28.55", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-28-hppa64", ver:"2.6.15-28.55", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-28-hppa64-smp", ver:"2.6.15-28.55", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-28-itanium", ver:"2.6.15-28.55", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-28-itanium-smp", ver:"2.6.15-28.55", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-28-k7", ver:"2.6.15-28.55", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-28-mckinley", ver:"2.6.15-28.55", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-28-mckinley-smp", ver:"2.6.15-28.55", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-28-powerpc", ver:"2.6.15-28.55", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-28-powerpc-smp", ver:"2.6.15-28.55", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-28-powerpc64-smp", ver:"2.6.15-28.55", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-28-server", ver:"2.6.15-28.55", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-28-server-bigiron", ver:"2.6.15-28.55", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-28-sparc64", ver:"2.6.15-28.55", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-28-sparc64-smp", ver:"2.6.15-28.55", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU6.10") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.17-11-386", ver:"2.6.17.1-11.38", rls:"UBUNTU6.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.17-11-generic", ver:"2.6.17.1-11.38", rls:"UBUNTU6.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.17-11-hppa32", ver:"2.6.17.1-11.38", rls:"UBUNTU6.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.17-11-hppa64", ver:"2.6.17.1-11.38", rls:"UBUNTU6.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.17-11-itanium", ver:"2.6.17.1-11.38", rls:"UBUNTU6.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.17-11-mckinley", ver:"2.6.17.1-11.38", rls:"UBUNTU6.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.17-11-powerpc", ver:"2.6.17.1-11.38", rls:"UBUNTU6.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.17-11-powerpc-smp", ver:"2.6.17.1-11.38", rls:"UBUNTU6.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.17-11-powerpc64-smp", ver:"2.6.17.1-11.38", rls:"UBUNTU6.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.17-11-server", ver:"2.6.17.1-11.38", rls:"UBUNTU6.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.17-11-server-bigiron", ver:"2.6.17.1-11.38", rls:"UBUNTU6.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.17-11-sparc64", ver:"2.6.17.1-11.38", rls:"UBUNTU6.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.17-11-sparc64-smp", ver:"2.6.17.1-11.38", rls:"UBUNTU6.10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU7.04") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.20-16-386", ver:"2.6.20-16.28", rls:"UBUNTU7.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.20-16-generic", ver:"2.6.20-16.28", rls:"UBUNTU7.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.20-16-hppa32", ver:"2.6.20-16.28", rls:"UBUNTU7.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.20-16-hppa64", ver:"2.6.20-16.28", rls:"UBUNTU7.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.20-16-itanium", ver:"2.6.20-16.28", rls:"UBUNTU7.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.20-16-lowlatency", ver:"2.6.20-16.28", rls:"UBUNTU7.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.20-16-mckinley", ver:"2.6.20-16.28", rls:"UBUNTU7.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.20-16-powerpc", ver:"2.6.20-16.28", rls:"UBUNTU7.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.20-16-powerpc-smp", ver:"2.6.20-16.28", rls:"UBUNTU7.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.20-16-powerpc64-smp", ver:"2.6.20-16.28", rls:"UBUNTU7.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.20-16-server", ver:"2.6.20-16.28", rls:"UBUNTU7.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.20-16-server-bigiron", ver:"2.6.20-16.28", rls:"UBUNTU7.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.20-16-sparc64", ver:"2.6.20-16.28", rls:"UBUNTU7.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.20-16-sparc64-smp", ver:"2.6.20-16.28", rls:"UBUNTU7.04"))) {
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
