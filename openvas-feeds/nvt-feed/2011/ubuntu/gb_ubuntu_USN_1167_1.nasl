# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840699");
  script_cve_id("CVE-2011-0463", "CVE-2011-1017", "CVE-2011-1078", "CVE-2011-1079", "CVE-2011-1080", "CVE-2011-1093", "CVE-2011-1160", "CVE-2011-1170", "CVE-2011-1171", "CVE-2011-1172", "CVE-2011-1173", "CVE-2011-1180", "CVE-2011-1476", "CVE-2011-1477", "CVE-2011-1479", "CVE-2011-1494", "CVE-2011-1495", "CVE-2011-1593", "CVE-2011-1598", "CVE-2011-1745", "CVE-2011-1746", "CVE-2011-1748", "CVE-2011-1759", "CVE-2011-1770", "CVE-2011-1771", "CVE-2011-1776", "CVE-2011-1927", "CVE-2011-2022", "CVE-2011-2479", "CVE-2011-2496", "CVE-2011-2498", "CVE-2011-2534", "CVE-2011-3359", "CVE-2011-3363", "CVE-2011-4913");
  script_tag(name:"creation_date", value:"2011-07-18 13:23:56 +0000 (Mon, 18 Jul 2011)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2013-06-10 13:37:00 +0000 (Mon, 10 Jun 2013)");

  script_name("Ubuntu: Security Advisory (USN-1167-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU11\.04");

  script_xref(name:"Advisory-ID", value:"USN-1167-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1167-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux' package(s) announced via the USN-1167-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Aristide Fattori and Roberto Paleari reported a flaw in the Linux kernel's
handling of IPv4 icmp packets. A remote user could exploit this to cause a
denial of service. (CVE-2011-1927)

Goldwyn Rodrigues discovered that the OCFS2 filesystem did not correctly
clear memory when writing certain file holes. A local attacker could
exploit this to read uninitialized data from the disk, leading to a loss of
privacy. (CVE-2011-0463)

Timo Warns discovered that the LDM disk partition handling code did not
correctly handle certain values. By inserting a specially crafted disk
device, a local attacker could exploit this to gain root privileges.
(CVE-2011-1017)

Vasiliy Kulikov discovered that the Bluetooth stack did not correctly clear
memory. A local attacker could exploit this to read kernel stack memory,
leading to a loss of privacy. (CVE-2011-1078)

Vasiliy Kulikov discovered that the Bluetooth stack did not correctly check
that device name strings were NULL terminated. A local attacker could
exploit this to crash the system, leading to a denial of service, or leak
contents of kernel stack memory, leading to a loss of privacy.
(CVE-2011-1079)

Vasiliy Kulikov discovered that bridge network filtering did not check that
name fields were NULL terminated. A local attacker could exploit this to
leak contents of kernel stack memory, leading to a loss of privacy.
(CVE-2011-1080)

Johan Hovold discovered that the DCCP network stack did not correctly
handle certain packet combinations. A remote attacker could send specially
crafted network traffic that would crash the system, leading to a denial of
service. (CVE-2011-1093)

Peter Huewe discovered that the TPM device did not correctly initialize
memory. A local attacker could exploit this to read kernel heap memory
contents, leading to a loss of privacy. (CVE-2011-1160)

Vasiliy Kulikov discovered that the netfilter code did not check certain
strings copied from userspace. A local attacker with netfilter access could
exploit this to read kernel memory or crash the system, leading to a denial
of service. (CVE-2011-1170, CVE-2011-1171, CVE-2011-1172, CVE-2011-2534)

Vasiliy Kulikov discovered that the Acorn Universal Networking driver did
not correctly initialize memory. A remote attacker could send specially
crafted traffic to read kernel stack memory, leading to a loss of privacy.
(CVE-2011-1173)

Dan Rosenberg discovered that the IRDA subsystem did not correctly check
certain field sizes. If a system was using IRDA, a remote attacker could
send specially crafted traffic to crash the system or gain root privileges.
(CVE-2011-1180)

Dan Rosenberg reported errors in the OSS (Open Sound System) MIDI
interface. A local attacker on non-x86 systems might be able to cause a
denial of service. (CVE-2011-1476)

Dan Rosenberg reported errors in the kernel's OSS (Open Sound System)
driver for Yamaha FM synthesizer chips. A local user can exploit ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux' package(s) on Ubuntu 11.04.");

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

if(release == "UBUNTU11.04") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.38-10-generic", ver:"2.6.38-10.46", rls:"UBUNTU11.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.38-10-generic-pae", ver:"2.6.38-10.46", rls:"UBUNTU11.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.38-10-omap", ver:"2.6.38-10.46", rls:"UBUNTU11.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.38-10-powerpc", ver:"2.6.38-10.46", rls:"UBUNTU11.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.38-10-powerpc-smp", ver:"2.6.38-10.46", rls:"UBUNTU11.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.38-10-powerpc64-smp", ver:"2.6.38-10.46", rls:"UBUNTU11.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.38-10-server", ver:"2.6.38-10.46", rls:"UBUNTU11.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.38-10-versatile", ver:"2.6.38-10.46", rls:"UBUNTU11.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.38-10-virtual", ver:"2.6.38-10.46", rls:"UBUNTU11.04"))) {
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
