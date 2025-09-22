# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841040");
  script_cve_id("CVE-2011-4131", "CVE-2012-2121", "CVE-2012-2133", "CVE-2012-2313", "CVE-2012-2319", "CVE-2012-2383", "CVE-2012-2384");
  script_tag(name:"creation_date", value:"2012-06-15 04:16:53 +0000 (Fri, 15 Jun 2012)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-1472-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU11\.10");

  script_xref(name:"Advisory-ID", value:"USN-1472-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1472-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux' package(s) announced via the USN-1472-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Andy Adamson discovered a flaw in the Linux kernel's NFSv4 implementation.
A remote NFS server (attacker) could exploit this flaw to cause a denial of
service. (CVE-2011-4131)

A flaw was discovered in the Linux kernel's KVM (kernel virtual machine).
An administrative user in the guest OS could leverage this flaw to cause a
denial of service in the host OS. (CVE-2012-2121)

Schacher Raindel discovered a flaw in the Linux kernel's memory handling
when hugetlb is enabled. An unprivileged local attacker could exploit this
flaw to cause a denial of service and potentially gain higher privileges.
(CVE-2012-2133)

Stephan Mueller reported a flaw in the Linux kernel's dl2k network driver's
handling of ioctls. An unprivileged local user could leverage this flaw to
cause a denial of service. (CVE-2012-2313)

Timo Warns reported multiple flaws in the Linux kernel's hfsplus
filesystem. An unprivileged local user could exploit these flaws to gain
root system privileges. (CVE-2012-2319)

Xi Wang discovered a flaw in the Linux kernel's i915 graphics driver
handling of cliprect on 32 bit systems. An unprivileged local attacker
could leverage this flaw to cause a denial of service or potentially gain
root privileges. (CVE-2012-2383)

Xi Wang discovered a flaw in the Linux kernel's i915 graphics driver
handling of buffer_count on 32 bit systems. An unprivileged local attacker
could leverage this flaw to cause a denial of service or potentially gain
root privileges. (CVE-2012-2384)");

  script_tag(name:"affected", value:"'linux' package(s) on Ubuntu 11.10.");

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

if(release == "UBUNTU11.10") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.0.0-21-generic", ver:"3.0.0-21.35", rls:"UBUNTU11.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.0.0-21-generic-pae", ver:"3.0.0-21.35", rls:"UBUNTU11.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.0.0-21-omap", ver:"3.0.0-21.35", rls:"UBUNTU11.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.0.0-21-powerpc", ver:"3.0.0-21.35", rls:"UBUNTU11.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.0.0-21-powerpc-smp", ver:"3.0.0-21.35", rls:"UBUNTU11.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.0.0-21-powerpc64-smp", ver:"3.0.0-21.35", rls:"UBUNTU11.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.0.0-21-server", ver:"3.0.0-21.35", rls:"UBUNTU11.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.0.0-21-virtual", ver:"3.0.0-21.35", rls:"UBUNTU11.10"))) {
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
