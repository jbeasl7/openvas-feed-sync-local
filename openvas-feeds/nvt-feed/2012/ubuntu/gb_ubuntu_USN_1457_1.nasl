# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841021");
  script_cve_id("CVE-2011-4131", "CVE-2012-1601", "CVE-2012-2121", "CVE-2012-2123", "CVE-2012-2133");
  script_tag(name:"creation_date", value:"2012-06-01 04:21:39 +0000 (Fri, 01 Jun 2012)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-1457-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU11\.04");

  script_xref(name:"Advisory-ID", value:"USN-1457-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1457-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux' package(s) announced via the USN-1457-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Andy Adamson discovered a flaw in the Linux kernel's NFSv4 implementation.
A remote NFS server (attacker) could exploit this flaw to cause a denial of
service. (CVE-2011-4131)

A flaw was found in the Linux kernel's KVM (Kernel Virtual Machine) virtual
cpu setup. An unprivileged local user could exploit this flaw to crash the
system leading to a denial of service. (CVE-2012-1601)

A flaw was discovered in the Linux kernel's KVM (kernel virtual machine).
An administrative user in the guest OS could leverage this flaw to cause a
denial of service in the host OS. (CVE-2012-2121)

Steve Grubb reported a flaw with Linux fscaps (file system base
capabilities) when used to increase the permissions of a process. For
application on which fscaps are in use a local attacker can disable address
space randomization to make attacking the process with raised privileges
easier. (CVE-2012-2123)

Schacher Raindel discovered a flaw in the Linux kernel's memory handling
when hugetlb is enabled. An unprivileged local attacker could exploit this
flaw to cause a denial of service and potentially gain higher privileges.
(CVE-2012-2133)");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.38-15-generic", ver:"2.6.38-15.60", rls:"UBUNTU11.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.38-15-generic-pae", ver:"2.6.38-15.60", rls:"UBUNTU11.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.38-15-omap", ver:"2.6.38-15.60", rls:"UBUNTU11.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.38-15-powerpc", ver:"2.6.38-15.60", rls:"UBUNTU11.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.38-15-powerpc-smp", ver:"2.6.38-15.60", rls:"UBUNTU11.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.38-15-powerpc64-smp", ver:"2.6.38-15.60", rls:"UBUNTU11.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.38-15-server", ver:"2.6.38-15.60", rls:"UBUNTU11.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.38-15-versatile", ver:"2.6.38-15.60", rls:"UBUNTU11.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.38-15-virtual", ver:"2.6.38-15.60", rls:"UBUNTU11.04"))) {
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
