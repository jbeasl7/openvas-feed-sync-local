# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.56014");
  script_cve_id("CVE-2004-2302", "CVE-2005-0756", "CVE-2005-0757", "CVE-2005-1265", "CVE-2005-1761", "CVE-2005-1762", "CVE-2005-1763", "CVE-2005-1765", "CVE-2005-1767", "CVE-2005-2456", "CVE-2005-2458", "CVE-2005-2459", "CVE-2005-2548", "CVE-2005-2801", "CVE-2005-2872", "CVE-2005-3105", "CVE-2005-3106", "CVE-2005-3107", "CVE-2005-3108", "CVE-2005-3109", "CVE-2005-3110", "CVE-2005-3271", "CVE-2005-3272", "CVE-2005-3273", "CVE-2005-3274", "CVE-2005-3275", "CVE-2005-3276");
  script_tag(name:"creation_date", value:"2008-01-17 22:07:13 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-02-19T05:05:57+0000");
  script_tag(name:"last_modification", value:"2024-02-19 05:05:57 +0000 (Mon, 19 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-16 16:53:52 +0000 (Fri, 16 Feb 2024)");

  script_name("Debian: Security Advisory (DSA-922-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.1");

  script_xref(name:"Advisory-ID", value:"DSA-922-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2005/DSA-922-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-922");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'kernel-image-2.6.8-alpha, kernel-image-2.6.8-amd64, kernel-image-2.6.8-hppa, kernel-image-2.6.8-i386, kernel-image-2.6.8-ia64, kernel-image-2.6.8-m68k, kernel-image-2.6.8-s390, kernel-image-2.6.8-sparc, kernel-patch-powerpc-2.6.8, kernel-source-2.6.8' package(s) announced via the DSA-922-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several local and remote vulnerabilities have been discovered in the Linux kernel that may lead to a denial of service or the execution of arbitrary code. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2004-2302

A race condition in the sysfs filesystem allows local users to read kernel memory and cause a denial of service (crash).

CVE-2005-0756

Alexander Nyberg discovered that the ptrace() system call does not properly verify addresses on the amd64 architecture which can be exploited by a local attacker to crash the kernel.

CVE-2005-0757

A problem in the offset handling in the xattr file system code for ext3 has been discovered that may allow users on 64-bit systems that have access to an ext3 filesystem with extended attributes to cause the kernel to crash.

CVE-2005-1265

Chris Wright discovered that the mmap() function could create illegal memory maps that could be exploited by a local user to crash the kernel or potentially execute arbitrary code.

CVE-2005-1761

A vulnerability on the IA-64 architecture can lead local attackers to overwrite kernel memory and crash the kernel.

CVE-2005-1762

A vulnerability has been discovered in the ptrace() system call on the amd64 architecture that allows a local attacker to cause the kernel to crash.

CVE-2005-1763

A buffer overflow in the ptrace system call for 64-bit architectures allows local users to write bytes into arbitrary kernel memory.

CVE-2005-1765

Zou Nan Hai has discovered that a local user could cause the kernel to hang on the amd64 architecture after invoking syscall() with specially crafted arguments.

CVE-2005-1767

A vulnerability has been discovered in the stack segment fault handler that could allow a local attacker to cause a stack exception that will lead the kernel to crash under certain circumstances.

CVE-2005-2456

Balazs Scheidler discovered that a local attacker could call setsockopt() with an invalid xfrm_user policy message which would cause the kernel to write beyond the boundaries of an array and crash.

CVE-2005-2458

Vladimir Volovich discovered a bug in the zlib routines which are also present in the Linux kernel and allows remote attackers to crash the kernel.

CVE-2005-2459

Another vulnerability has been discovered in the zlib routines which are also present in the Linux kernel and allows remote attackers to crash the kernel.

CVE-2005-2548

Peter Sandstrom noticed that snmpwalk from a remote host could cause a denial of service (kernel oops from null dereference) via certain UDP packets that lead to a function call with the wrong argument.

CVE-2005-2801

Andreas Gruenbacher discovered a bug in the ext2 and ext3 file systems. When data areas are to be shared among two inodes not all information were compared for equality, which could expose wrong ACLs for files.

CVE-2005-2872

Chad Walstrom discovered that the ipt_recent kernel module on ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel-image-2.6.8-alpha, kernel-image-2.6.8-amd64, kernel-image-2.6.8-hppa, kernel-image-2.6.8-i386, kernel-image-2.6.8-ia64, kernel-image-2.6.8-m68k, kernel-image-2.6.8-s390, kernel-image-2.6.8-sparc, kernel-patch-powerpc-2.6.8, kernel-source-2.6.8' package(s) on Debian 3.1.");

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

if(release == "DEB3.1") {

  if(!isnull(res = isdpkgvuln(pkg:"kernel-build-2.6.8-2", ver:"2.6.8-15sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-build-2.6.8-power3", ver:"2.6.8-12sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-build-2.6.8-power3-smp", ver:"2.6.8-12sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-build-2.6.8-power4", ver:"2.6.8-12sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-build-2.6.8-power4-smp", ver:"2.6.8-12sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-build-2.6.8-powerpc", ver:"2.6.8-12sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-build-2.6.8-powerpc-smp", ver:"2.6.8-12sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-doc-2.6.8", ver:"2.6.8-16sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-headers-2.6-itanium", ver:"2.6.8-14sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-headers-2.6-itanium-smp", ver:"2.6.8-14sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-headers-2.6-mckinley", ver:"2.6.8-14sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-headers-2.6-mckinley-smp", ver:"2.6.8-14sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-headers-2.6.8", ver:"2.6.8-12sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-headers-2.6.8-11", ver:"2.6.8-16sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-headers-2.6.8-11-amd64-generic", ver:"2.6.8-16sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-headers-2.6.8-11-amd64-k8", ver:"2.6.8-16sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-headers-2.6.8-11-amd64-k8-smp", ver:"2.6.8-16sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-headers-2.6.8-11-em64t-p4", ver:"2.6.8-16sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-headers-2.6.8-11-em64t-p4-smp", ver:"2.6.8-16sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-headers-2.6.8-2", ver:"2.6.8-14sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-headers-2.6.8-2", ver:"2.6.8-15sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-headers-2.6.8-2", ver:"2.6.8-16sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-headers-2.6.8-2", ver:"2.6.8-5sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-headers-2.6.8-2", ver:"2.6.8-6sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-headers-2.6.8-2-32", ver:"2.6.8-6sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-headers-2.6.8-2-32-smp", ver:"2.6.8-6sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-headers-2.6.8-2-386", ver:"2.6.8-16sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-headers-2.6.8-2-64", ver:"2.6.8-6sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-headers-2.6.8-2-64-smp", ver:"2.6.8-6sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-headers-2.6.8-2-686", ver:"2.6.8-16sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-headers-2.6.8-2-686-smp", ver:"2.6.8-16sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-headers-2.6.8-2-generic", ver:"2.6.8-16sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-headers-2.6.8-2-itanium", ver:"2.6.8-14sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-headers-2.6.8-2-itanium-smp", ver:"2.6.8-14sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-headers-2.6.8-2-k7", ver:"2.6.8-16sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-headers-2.6.8-2-k7-smp", ver:"2.6.8-16sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-headers-2.6.8-2-mckinley", ver:"2.6.8-14sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-headers-2.6.8-2-mckinley-smp", ver:"2.6.8-14sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-headers-2.6.8-2-smp", ver:"2.6.8-16sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-headers-2.6.8-2-sparc32", ver:"2.6.8-15sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-headers-2.6.8-2-sparc64", ver:"2.6.8-15sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-headers-2.6.8-2-sparc64-smp", ver:"2.6.8-15sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-2.6-itanium", ver:"2.6.8-14sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-2.6-itanium-smp", ver:"2.6.8-14sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-2.6-mckinley", ver:"2.6.8-14sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-2.6-mckinley-smp", ver:"2.6.8-14sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-2.6.8-11-amd64-generic", ver:"2.6.8-16sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-2.6.8-11-amd64-k8", ver:"2.6.8-16sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-2.6.8-11-amd64-k8-smp", ver:"2.6.8-16sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-2.6.8-11-em64t-p4", ver:"2.6.8-16sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-2.6.8-11-em64t-p4-smp", ver:"2.6.8-16sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-2.6.8-2-32", ver:"2.6.8-6sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-2.6.8-2-32-smp", ver:"2.6.8-6sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-2.6.8-2-386", ver:"2.6.8-16sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-2.6.8-2-64", ver:"2.6.8-6sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-2.6.8-2-64-smp", ver:"2.6.8-6sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-2.6.8-2-686", ver:"2.6.8-16sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-2.6.8-2-686-smp", ver:"2.6.8-16sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-2.6.8-2-generic", ver:"2.6.8-16sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-2.6.8-2-itanium", ver:"2.6.8-14sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-2.6.8-2-itanium-smp", ver:"2.6.8-14sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-2.6.8-2-k7", ver:"2.6.8-16sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-2.6.8-2-k7-smp", ver:"2.6.8-16sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-2.6.8-2-mckinley", ver:"2.6.8-14sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-2.6.8-2-mckinley-smp", ver:"2.6.8-14sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-2.6.8-2-s390", ver:"2.6.8-5sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-2.6.8-2-s390-tape", ver:"2.6.8-5sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-2.6.8-2-s390x", ver:"2.6.8-5sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-2.6.8-2-smp", ver:"2.6.8-16sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-2.6.8-2-sparc32", ver:"2.6.8-15sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-2.6.8-2-sparc64", ver:"2.6.8-15sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-2.6.8-2-sparc64-smp", ver:"2.6.8-15sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-2.6.8-amiga", ver:"2.6.8-4sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-2.6.8-atari", ver:"2.6.8-4sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-2.6.8-bvme6000", ver:"2.6.8-4sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-2.6.8-hp", ver:"2.6.8-4sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-2.6.8-mac", ver:"2.6.8-4sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-2.6.8-mvme147", ver:"2.6.8-4sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-2.6.8-mvme16x", ver:"2.6.8-4sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-2.6.8-power3", ver:"2.6.8-12sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-2.6.8-power3-smp", ver:"2.6.8-12sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-2.6.8-power4", ver:"2.6.8-12sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-2.6.8-power4-smp", ver:"2.6.8-12sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-2.6.8-powerpc", ver:"2.6.8-12sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-2.6.8-powerpc-smp", ver:"2.6.8-12sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-2.6.8-q40", ver:"2.6.8-4sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-2.6.8-sun3", ver:"2.6.8-4sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-patch-2.6.8-s390", ver:"2.6.8-5sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-patch-debian-2.6.8", ver:"2.6.8-16sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-source-2.6.8", ver:"2.6.8-16sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-tree-2.6.8", ver:"2.6.8-16sarge1", rls:"DEB3.1"))) {
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
