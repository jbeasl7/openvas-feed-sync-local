# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840099");
  script_cve_id("CVE-2006-4572", "CVE-2006-4814", "CVE-2006-5749", "CVE-2006-5753", "CVE-2006-5755", "CVE-2006-5757", "CVE-2006-5823", "CVE-2006-6053", "CVE-2006-6054", "CVE-2006-6056", "CVE-2006-6057", "CVE-2006-6106");
  script_tag(name:"creation_date", value:"2009-03-23 09:55:18 +0000 (Mon, 23 Mar 2009)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Ubuntu: Security Advisory (USN-416-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(5\.10|6\.06\ LTS|6\.10)");

  script_xref(name:"Advisory-ID", value:"USN-416-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-416-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-meta, linux-restricted-modules-2.6.15, linux-restricted-modules-2.6.17, linux-source-2.6.12, linux-source-2.6.15, linux-source-2.6.17' package(s) announced via the USN-416-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Mark Dowd discovered that the netfilter iptables module did not
correctly handle fragmented IPv6 packets. By sending specially crafted
packets, a remote attacker could exploit this to bypass firewall
rules. This has already been fixed for Ubuntu 6.10 in USN-395-1,
this is the corresponding fix for Ubuntu 6.06.(CVE-2006-4572)

Doug Chapman discovered an improper lock handling in the mincore()
function. A local attacker could exploit this to cause an eternal hang
in the kernel, rendering the machine unusable. (CVE-2006-4814)

Al Viro reported that the ISDN PPP module did not initialize the reset
state timer. By sending specially crafted ISDN packets, a remote
attacker could exploit this to crash the kernel. (CVE-2006-5749)

Various syscalls (like listxattr()) misinterpreted the return value of
return_EIO() when encountering bad inodes. By issuing particular
system calls on a malformed file system, a local attacker could
exploit this to crash the kernel. (CVE-2006-5753)

The task switching code did not save and restore EFLAGS of processes.
By starting a specially crafted executable, a local attacker could
exploit this to eventually crash many other running processes. This
only affects the amd64 platform. (CVE-2006-5755)

A race condition was found in the grow_buffers() function. By mounting
a specially crafted ISO9660 or NTFS file system, a local attacker
could exploit this to trigger an infinite loop in the kernel,
rendering the machine unusable. (CVE-2006-5757)

A buffer overread was found in the zlib_inflate() function. By
tricking an user into mounting a specially crafted file system which
uses zlib compression (such as cramfs), this could be exploited to
crash the kernel. (CVE-2006-5823)

The ext3 file system driver did not properly handle corrupted data
structures. By mounting a specially crafted ext3 file system, a local
attacker could exploit this to crash the kernel. (CVE-2006-6053)

The ext2 file system driver did not properly handle corrupted data
structures. By mounting a specially crafted ext2 file system, a local
attacker could exploit this to crash the kernel. (CVE-2006-6054)

The hfs file system driver did not properly handle corrupted data
structures. By mounting a specially crafted hfs file system, a local
attacker could exploit this to crash the kernel. This only affects
systems which enable SELinux (Ubuntu disables SELinux by default).
(CVE-2006-6056)

Several vulnerabilities have been found in the GFS2 file system
driver. Since this driver has never actually worked in Ubuntu 6.10, it
has been disabled. This only affects Ubuntu 6.10. (CVE-2006-6057)

Marcel Holtman discovered several buffer overflows in the Bluetooth
driver. By sending Bluetooth packets with specially crafted CAPI
messages, a remote attacker could exploit these to crash the kernel.
(CVE-2006-6106)");

  script_tag(name:"affected", value:"'linux-meta, linux-restricted-modules-2.6.15, linux-restricted-modules-2.6.17, linux-source-2.6.12, linux-source-2.6.15, linux-source-2.6.17' package(s) on Ubuntu 5.10, Ubuntu 6.06, Ubuntu 6.10.");

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

if(release == "UBUNTU5.10") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.12-10-386", ver:"2.6.12-10.45", rls:"UBUNTU5.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.12-10-686", ver:"2.6.12-10.45", rls:"UBUNTU5.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.12-10-686-smp", ver:"2.6.12-10.45", rls:"UBUNTU5.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.12-10-amd64-generic", ver:"2.6.12-10.45", rls:"UBUNTU5.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.12-10-amd64-k8", ver:"2.6.12-10.45", rls:"UBUNTU5.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.12-10-amd64-k8-smp", ver:"2.6.12-10.45", rls:"UBUNTU5.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.12-10-amd64-xeon", ver:"2.6.12-10.45", rls:"UBUNTU5.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.12-10-k7", ver:"2.6.12-10.45", rls:"UBUNTU5.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.12-10-k7-smp", ver:"2.6.12-10.45", rls:"UBUNTU5.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.12-10-powerpc", ver:"2.6.12-10.45", rls:"UBUNTU5.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.12-10-powerpc-smp", ver:"2.6.12-10.45", rls:"UBUNTU5.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.12-10-powerpc64-smp", ver:"2.6.12-10.45", rls:"UBUNTU5.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-patch-ubuntu-2.6.12", ver:"2.6.12-10.45", rls:"UBUNTU5.10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU6.06 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-28-386", ver:"2.6.15-28.51", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-28-686", ver:"2.6.15-28.51", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-28-amd64-generic", ver:"2.6.15-28.51", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-28-amd64-k8", ver:"2.6.15-28.51", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-28-amd64-server", ver:"2.6.15-28.51", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-28-amd64-xeon", ver:"2.6.15-28.51", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-28-k7", ver:"2.6.15-28.51", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-28-powerpc", ver:"2.6.15-28.51", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-28-powerpc-smp", ver:"2.6.15-28.51", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-28-powerpc64-smp", ver:"2.6.15-28.51", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-28-server", ver:"2.6.15-28.51", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-28-server-bigiron", ver:"2.6.15-28.51", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-28-sparc64", ver:"2.6.15-28.51", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-28-sparc64-smp", ver:"2.6.15-28.51", rls:"UBUNTU6.06 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.17-11-386", ver:"2.6.17.1-11.35", rls:"UBUNTU6.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.17-11-generic", ver:"2.6.17.1-11.35", rls:"UBUNTU6.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.17-11-powerpc", ver:"2.6.17.1-11.35", rls:"UBUNTU6.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.17-11-powerpc-smp", ver:"2.6.17.1-11.35", rls:"UBUNTU6.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.17-11-powerpc64-smp", ver:"2.6.17.1-11.35", rls:"UBUNTU6.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.17-11-server", ver:"2.6.17.1-11.35", rls:"UBUNTU6.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.17-11-server-bigiron", ver:"2.6.17.1-11.35", rls:"UBUNTU6.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.17-11-sparc64", ver:"2.6.17.1-11.35", rls:"UBUNTU6.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.17-11-sparc64-smp", ver:"2.6.17.1-11.35", rls:"UBUNTU6.10"))) {
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
