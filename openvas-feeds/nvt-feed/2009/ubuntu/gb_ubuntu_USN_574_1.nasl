# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840307");
  script_cve_id("CVE-2006-6058", "CVE-2007-3107", "CVE-2007-4567", "CVE-2007-4849", "CVE-2007-4997", "CVE-2007-5093", "CVE-2007-5500", "CVE-2007-5501", "CVE-2007-5966", "CVE-2007-6063", "CVE-2007-6151", "CVE-2007-6206", "CVE-2007-6417", "CVE-2008-0001");
  script_tag(name:"creation_date", value:"2009-03-23 09:59:50 +0000 (Mon, 23 Mar 2009)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_name("Ubuntu: Security Advisory (USN-574-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(6\.10|7\.04|7\.10)");

  script_xref(name:"Advisory-ID", value:"USN-574-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-574-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-source-2.6.17, linux-source-2.6.20, linux-source-2.6.22' package(s) announced via the USN-574-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The minix filesystem did not properly validate certain filesystem
values. If a local attacker could trick the system into attempting
to mount a corrupted minix filesystem, the kernel could be made to
hang for long periods of time, resulting in a denial of service.
This was only vulnerable in Ubuntu 7.04 and 7.10. (CVE-2006-6058)

The signal handling on PowerPC systems using HTX allowed local users
to cause a denial of service via floating point corruption. This was
only vulnerable in Ubuntu 6.10 and 7.04. (CVE-2007-3107)

The Linux kernel did not properly validate the hop-by-hop IPv6
extended header. Remote attackers could send a crafted IPv6 packet
and cause a denial of service via kernel panic. This was only
vulnerable in Ubuntu 7.04. (CVE-2007-4567)

The JFFS2 filesystem with ACL support enabled did not properly store
permissions during inode creation and ACL setting. Local users could
possibly access restricted files after a remount. This was only
vulnerable in Ubuntu 7.04 and 7.10. (CVE-2007-4849)

Chris Evans discovered an issue with certain drivers that use the
ieee80211_rx function. Remote attackers could send a crafted 802.11
frame and cause a denial of service via crash. This was only
vulnerable in Ubuntu 7.04 and 7.10. (CVE-2007-4997)

Alex Smith discovered an issue with the pwc driver for certain webcam
devices. A local user with physical access to the system could remove
the device while a userspace application had it open and cause the USB
subsystem to block. This was only vulnerable in Ubuntu 7.04.
(CVE-2007-5093)

Scott James Remnant discovered a coding error in ptrace. Local users
could exploit this and cause the kernel to enter an infinite loop.
This was only vulnerable in Ubuntu 7.04 and 7.10. (CVE-2007-5500)

It was discovered that the Linux kernel could dereference a NULL
pointer when processing certain IPv4 TCP packets. A remote attacker
could send a crafted TCP ACK response and cause a denial of service
via crash. This was only vulnerable in Ubuntu 7.10. (CVE-2007-5501)

Warren Togami discovered that the hrtimer subsystem did not properly
check for large relative timeouts. A local user could exploit this and
cause a denial of service via soft lockup. (CVE-2007-5966)

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
rare ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux-source-2.6.17, linux-source-2.6.20, linux-source-2.6.22' package(s) on Ubuntu 6.10, Ubuntu 7.04, Ubuntu 7.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.17-12-386", ver:"2.6.17.1-12.43", rls:"UBUNTU6.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.17-12-generic", ver:"2.6.17.1-12.43", rls:"UBUNTU6.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.17-12-hppa32", ver:"2.6.17.1-12.43", rls:"UBUNTU6.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.17-12-hppa64", ver:"2.6.17.1-12.43", rls:"UBUNTU6.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.17-12-itanium", ver:"2.6.17.1-12.43", rls:"UBUNTU6.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.17-12-mckinley", ver:"2.6.17.1-12.43", rls:"UBUNTU6.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.17-12-powerpc", ver:"2.6.17.1-12.43", rls:"UBUNTU6.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.17-12-powerpc-smp", ver:"2.6.17.1-12.43", rls:"UBUNTU6.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.17-12-powerpc64-smp", ver:"2.6.17.1-12.43", rls:"UBUNTU6.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.17-12-server", ver:"2.6.17.1-12.43", rls:"UBUNTU6.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.17-12-server-bigiron", ver:"2.6.17.1-12.43", rls:"UBUNTU6.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.17-12-sparc64", ver:"2.6.17.1-12.43", rls:"UBUNTU6.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.17-12-sparc64-smp", ver:"2.6.17.1-12.43", rls:"UBUNTU6.10"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.20-16-386", ver:"2.6.20-16.34", rls:"UBUNTU7.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.20-16-generic", ver:"2.6.20-16.34", rls:"UBUNTU7.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.20-16-hppa32", ver:"2.6.20-16.34", rls:"UBUNTU7.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.20-16-hppa64", ver:"2.6.20-16.34", rls:"UBUNTU7.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.20-16-itanium", ver:"2.6.20-16.34", rls:"UBUNTU7.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.20-16-lowlatency", ver:"2.6.20-16.34", rls:"UBUNTU7.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.20-16-mckinley", ver:"2.6.20-16.34", rls:"UBUNTU7.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.20-16-powerpc", ver:"2.6.20-16.34", rls:"UBUNTU7.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.20-16-powerpc-smp", ver:"2.6.20-16.34", rls:"UBUNTU7.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.20-16-powerpc64-smp", ver:"2.6.20-16.34", rls:"UBUNTU7.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.20-16-server", ver:"2.6.20-16.34", rls:"UBUNTU7.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.20-16-server-bigiron", ver:"2.6.20-16.34", rls:"UBUNTU7.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.20-16-sparc64", ver:"2.6.20-16.34", rls:"UBUNTU7.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.20-16-sparc64-smp", ver:"2.6.20-16.34", rls:"UBUNTU7.04"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU7.10") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.22-14-386", ver:"2.6.22-14.51", rls:"UBUNTU7.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.22-14-cell", ver:"2.6.22-14.51", rls:"UBUNTU7.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.22-14-generic", ver:"2.6.22-14.51", rls:"UBUNTU7.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.22-14-hppa32", ver:"2.6.22-14.51", rls:"UBUNTU7.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.22-14-hppa64", ver:"2.6.22-14.51", rls:"UBUNTU7.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.22-14-itanium", ver:"2.6.22-14.51", rls:"UBUNTU7.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.22-14-lpia", ver:"2.6.22-14.51", rls:"UBUNTU7.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.22-14-lpiacompat", ver:"2.6.22-14.51", rls:"UBUNTU7.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.22-14-mckinley", ver:"2.6.22-14.51", rls:"UBUNTU7.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.22-14-powerpc", ver:"2.6.22-14.51", rls:"UBUNTU7.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.22-14-powerpc-smp", ver:"2.6.22-14.51", rls:"UBUNTU7.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.22-14-powerpc64-smp", ver:"2.6.22-14.51", rls:"UBUNTU7.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.22-14-rt", ver:"2.6.22-14.51", rls:"UBUNTU7.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.22-14-server", ver:"2.6.22-14.51", rls:"UBUNTU7.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.22-14-sparc64", ver:"2.6.22-14.51", rls:"UBUNTU7.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.22-14-sparc64-smp", ver:"2.6.22-14.51", rls:"UBUNTU7.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.22-14-ume", ver:"2.6.22-14.51", rls:"UBUNTU7.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.22-14-virtual", ver:"2.6.22-14.51", rls:"UBUNTU7.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.22-14-xen", ver:"2.6.22-14.51", rls:"UBUNTU7.10"))) {
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
