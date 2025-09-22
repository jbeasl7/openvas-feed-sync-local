# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842666");
  script_cve_id("CVE-2013-4312", "CVE-2015-8785", "CVE-2016-1575", "CVE-2016-1576", "CVE-2016-2069");
  script_tag(name:"creation_date", value:"2016-02-27 05:18:02 +0000 (Sat, 27 Feb 2016)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-05-04 18:23:39 +0000 (Wed, 04 May 2016)");

  script_name("Ubuntu: Security Advisory (USN-2908-4)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU15\.10");

  script_xref(name:"Advisory-ID", value:"USN-2908-4");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2908-4");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1548587");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux' package(s) announced via the USN-2908-4 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-2908-1 fixed vulnerabilities in the Linux kernel for Ubuntu
15.10. An incorrect locking fix caused a regression that broke
graphics displays for Ubuntu 15.10 guests running within VMWare
virtual machines. This update fixes the problem.

We apologize for the inconvenience.

Original advisory details:

 halfdog discovered that OverlayFS, when mounting on top of a FUSE mount,
 incorrectly propagated file attributes, including setuid. A local
 unprivileged attacker could use this to gain privileges. (CVE-2016-1576)

 halfdog discovered that OverlayFS in the Linux kernel incorrectly
 propagated security sensitive extended attributes, such as POSIX ACLs. A
 local unprivileged attacker could use this to gain privileges.
 (CVE-2016-1575)

 It was discovered that the Linux kernel did not properly enforce rlimits
 for file descriptors sent over UNIX domain sockets. A local attacker could
 use this to cause a denial of service. (CVE-2013-4312)

 It was discovered that the Linux kernel's Filesystem in Userspace (FUSE)
 implementation did not handle initial zero length segments properly. A
 local attacker could use this to cause a denial of service (unkillable
 task). (CVE-2015-8785)

 Andy Lutomirski discovered a race condition in the Linux kernel's
 translation lookaside buffer (TLB) handling of flush events. A local
 attacker could use this to cause a denial of service or possibly leak
 sensitive information. (CVE-2016-2069)");

  script_tag(name:"affected", value:"'linux' package(s) on Ubuntu 15.10.");

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

if(release == "UBUNTU15.10") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.2.0-30-generic", ver:"4.2.0-30.36", rls:"UBUNTU15.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.2.0-30-generic-lpae", ver:"4.2.0-30.36", rls:"UBUNTU15.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.2.0-30-lowlatency", ver:"4.2.0-30.36", rls:"UBUNTU15.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.2.0-30-powerpc-e500mc", ver:"4.2.0-30.36", rls:"UBUNTU15.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.2.0-30-powerpc-smp", ver:"4.2.0-30.36", rls:"UBUNTU15.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.2.0-30-powerpc64-emb", ver:"4.2.0-30.36", rls:"UBUNTU15.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.2.0-30-powerpc64-smp", ver:"4.2.0-30.36", rls:"UBUNTU15.10"))) {
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
