# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840330");
  script_cve_id("CVE-2006-6058", "CVE-2006-7229", "CVE-2007-4133", "CVE-2007-4997", "CVE-2007-5093", "CVE-2007-5500", "CVE-2007-6063", "CVE-2007-6151", "CVE-2007-6206", "CVE-2007-6417", "CVE-2008-0001");
  script_tag(name:"creation_date", value:"2009-03-23 09:59:50 +0000 (Mon, 23 Mar 2009)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_name("Ubuntu: Security Advisory (USN-578-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU6\.06\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-578-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-578-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-source-2.6.15' package(s) announced via the USN-578-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The minix filesystem did not properly validate certain filesystem
values. If a local attacker could trick the system into attempting
to mount a corrupted minix filesystem, the kernel could be made to
hang for long periods of time, resulting in a denial of service.
(CVE-2006-6058)

Alexander Schulze discovered that the skge driver does not properly
use the spin_lock and spin_unlock functions. Remote attackers could
exploit this by sending a flood of network traffic and cause a denial
of service (crash). (CVE-2006-7229)

Hugh Dickins discovered that hugetlbfs performed certain prio_tree
calculations using HPAGE_SIZE instead of PAGE_SIZE. A local user
could exploit this and cause a denial of service via kernel panic.
(CVE-2007-4133)

Chris Evans discovered an issue with certain drivers that use the
ieee80211_rx function. Remote attackers could send a crafted 802.11
frame and cause a denial of service via crash. (CVE-2007-4997)

Alex Smith discovered an issue with the pwc driver for certain webcam
devices. A local user with physical access to the system could remove
the device while a userspace application had it open and cause the USB
subsystem to block. (CVE-2007-5093)

Scott James Remnant discovered a coding error in ptrace. Local users
could exploit this and cause the kernel to enter an infinite loop.
(CVE-2007-5500)

Venustech AD-LAB discovered a buffer overflow in the isdn net
subsystem. This issue is exploitable by local users via crafted input
to the isdn_ioctl function. (CVE-2007-6063)

It was discovered that the isdn subsystem did not properly check for
NULL termination when performing ioctl handling. A local user could
exploit this to cause a denial of service. (CVE-2007-6151)

Blake Frantz discovered that when a root process overwrote an existing
core file, the resulting core file retained the previous core file's
ownership. Local users could exploit this to gain access to sensitive
information. (CVE-2007-6206)

Hugh Dickins discovered the when using the tmpfs filesystem, under
rare circumstances, a kernel page may be improperly cleared. A local
user may be able to exploit this and read sensitive kernel data or
cause a denial of service via crash. (CVE-2007-6417)

Bill Roman discovered that the VFS subsystem did not properly check
access modes. A local user may be able to gain removal privileges
on directories. (CVE-2008-0001)");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-51-386", ver:"2.6.15-51.66", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-51-686", ver:"2.6.15-51.66", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-51-amd64-generic", ver:"2.6.15-51.66", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-51-amd64-k8", ver:"2.6.15-51.66", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-51-amd64-server", ver:"2.6.15-51.66", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-51-amd64-xeon", ver:"2.6.15-51.66", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-51-hppa32", ver:"2.6.15-51.66", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-51-hppa32-smp", ver:"2.6.15-51.66", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-51-hppa64", ver:"2.6.15-51.66", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-51-hppa64-smp", ver:"2.6.15-51.66", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-51-itanium", ver:"2.6.15-51.66", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-51-itanium-smp", ver:"2.6.15-51.66", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-51-k7", ver:"2.6.15-51.66", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-51-mckinley", ver:"2.6.15-51.66", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-51-mckinley-smp", ver:"2.6.15-51.66", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-51-powerpc", ver:"2.6.15-51.66", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-51-powerpc-smp", ver:"2.6.15-51.66", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-51-powerpc64-smp", ver:"2.6.15-51.66", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-51-server", ver:"2.6.15-51.66", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-51-server-bigiron", ver:"2.6.15-51.66", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-51-sparc64", ver:"2.6.15-51.66", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-51-sparc64-smp", ver:"2.6.15-51.66", rls:"UBUNTU6.06 LTS"))) {
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
