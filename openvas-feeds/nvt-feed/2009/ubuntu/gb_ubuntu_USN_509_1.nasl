# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840076");
  script_cve_id("CVE-2007-3104", "CVE-2007-3105", "CVE-2007-3513", "CVE-2007-3848", "CVE-2007-3851", "CVE-2007-4308");
  script_tag(name:"creation_date", value:"2009-03-23 09:59:50 +0000 (Mon, 23 Mar 2009)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-509-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU6\.10");

  script_xref(name:"Advisory-ID", value:"USN-509-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-509-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-source-2.6.17' package(s) announced via the USN-509-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A flaw in the sysfs_readdir function allowed a local user to cause a
denial of service by dereferencing a NULL pointer. (CVE-2007-3104)

A buffer overflow was discovered in the random number generator. In
environments with granular assignment of root privileges, a local attacker
could gain additional privileges. (CVE-2007-3105)

A flaw was discovered in the usblcd driver. A local attacker could cause
large amounts of kernel memory consumption, leading to a denial of service.
(CVE-2007-3513)

It was discovered that certain setuid-root processes did not correctly
reset process death signal handlers. A local user could manipulate this
to send signals to processes they would not normally have access to.
(CVE-2007-3848)

The Direct Rendering Manager for the i915 driver could be made to write
to arbitrary memory locations. An attacker with access to a running X11
session could send a specially crafted buffer and gain root privileges.
(CVE-2007-3851)

It was discovered that the aacraid SCSI driver did not correctly check
permissions on certain ioctls. A local attacker could cause a denial
of service or gain privileges. (CVE-2007-4308)");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.17-12-386", ver:"2.6.17.1-12.40", rls:"UBUNTU6.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.17-12-generic", ver:"2.6.17.1-12.40", rls:"UBUNTU6.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.17-12-hppa32", ver:"2.6.17.1-12.40", rls:"UBUNTU6.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.17-12-hppa64", ver:"2.6.17.1-12.40", rls:"UBUNTU6.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.17-12-itanium", ver:"2.6.17.1-12.40", rls:"UBUNTU6.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.17-12-mckinley", ver:"2.6.17.1-12.40", rls:"UBUNTU6.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.17-12-powerpc", ver:"2.6.17.1-12.40", rls:"UBUNTU6.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.17-12-powerpc-smp", ver:"2.6.17.1-12.40", rls:"UBUNTU6.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.17-12-powerpc64-smp", ver:"2.6.17.1-12.40", rls:"UBUNTU6.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.17-12-server", ver:"2.6.17.1-12.40", rls:"UBUNTU6.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.17-12-server-bigiron", ver:"2.6.17.1-12.40", rls:"UBUNTU6.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.17-12-sparc64", ver:"2.6.17.1-12.40", rls:"UBUNTU6.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.17-12-sparc64-smp", ver:"2.6.17.1-12.40", rls:"UBUNTU6.10"))) {
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
