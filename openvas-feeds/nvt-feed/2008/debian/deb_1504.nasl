# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.60438");
  script_cve_id("CVE-2006-5823", "CVE-2006-6054", "CVE-2006-6058", "CVE-2006-7203", "CVE-2007-1353", "CVE-2007-2172", "CVE-2007-2525", "CVE-2007-3105", "CVE-2007-3739", "CVE-2007-3740", "CVE-2007-3848", "CVE-2007-4133", "CVE-2007-4308", "CVE-2007-4573", "CVE-2007-5093", "CVE-2007-6063", "CVE-2007-6151", "CVE-2007-6206", "CVE-2007-6694", "CVE-2008-0007");
  script_tag(name:"creation_date", value:"2008-02-28 01:09:28 +0000 (Thu, 28 Feb 2008)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_name("Debian: Security Advisory (DSA-1504-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.1");

  script_xref(name:"Advisory-ID", value:"DSA-1504-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2008/DSA-1504-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1504");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'fai-kernels, kernel-image-2.6.8-alpha, kernel-image-2.6.8-amd64, kernel-image-2.6.8-hppa, kernel-image-2.6.8-i386, kernel-image-2.6.8-ia64, kernel-image-2.6.8-m68k, kernel-image-2.6.8-s390, kernel-image-2.6.8-sparc, kernel-patch-powerpc-2.6.8, kernel-source-2.6.8' package(s) announced via the DSA-1504-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several local and remote vulnerabilities have been discovered in the Linux kernel that may lead to a denial of service or the execution of arbitrary code. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2006-5823

LMH reported a potential local DoS which could be exploited by a malicious user with the privileges to mount and read a corrupted cramfs filesystem.

CVE-2006-6054

LMH reported a potential local DoS which could be exploited by a malicious user with the privileges to mount and read a corrupted ext2 filesystem.

CVE-2006-6058

LMH reported an issue in the minix filesystem that allows local users with mount privileges to create a DoS (printk flood) by mounting a specially crafted corrupt filesystem.

CVE-2006-7203

OpenVZ Linux kernel team reported an issue in the smbfs filesystem which can be exploited by local users to cause a DoS (oops) during mount.

CVE-2007-1353

Ilja van Sprundel discovered that kernel memory could be leaked via the Bluetooth setsockopt call due to an uninitialized stack buffer. This could be used by local attackers to read the contents of sensitive kernel memory.

CVE-2007-2172

Thomas Graf reported a typo in the DECnet protocol handler that could be used by a local attacker to overrun an array via crafted packets, potentially resulting in a Denial of Service (system crash). A similar issue exists in the IPV4 protocol handler and will be fixed in a subsequent update.

CVE-2007-2525

Florian Zumbiehl discovered a memory leak in the PPPOE subsystem caused by releasing a socket before PPPIOCGCHAN is called upon it. This could be used by a local user to DoS a system by consuming all available memory.

CVE-2007-3105

The PaX Team discovered a potential buffer overflow in the random number generator which may permit local users to cause a denial of service or gain additional privileges. This issue is not believed to effect default Debian installations where only root has sufficient privileges to exploit it.

CVE-2007-3739

Adam Litke reported a potential local denial of service (oops) on powerpc platforms resulting from unchecked VMA expansion into address space reserved for hugetlb pages.

CVE-2007-3740

Steve French reported that CIFS filesystems with CAP_UNIX enabled were not honoring a process' umask which may lead to unintentionally relaxed permissions.

CVE-2007-3848

Wojciech Purczynski discovered that pdeath_signal was not being reset properly under certain conditions which may allow local users to gain privileges by sending arbitrary signals to suid binaries.

CVE-2007-4133

Hugh Dickins discovered a potential local DoS (panic) in hugetlbfs. A misconversion of hugetlb_vmtruncate_list to prio_tree may allow local users to trigger a BUG_ON() call in exit_mmap.

CVE-2007-4308

Alan Cox reported an issue in the aacraid driver that allows unprivileged local users to make ioctl calls which should be ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'fai-kernels, kernel-image-2.6.8-alpha, kernel-image-2.6.8-amd64, kernel-image-2.6.8-hppa, kernel-image-2.6.8-i386, kernel-image-2.6.8-ia64, kernel-image-2.6.8-m68k, kernel-image-2.6.8-s390, kernel-image-2.6.8-sparc, kernel-patch-powerpc-2.6.8, kernel-source-2.6.8' package(s) on Debian 3.1.");

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

  if(!isnull(res = isdpkgvuln(pkg:"fai-kernels", ver:"1.9.1sarge8", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-build-2.6.8-4", ver:"2.6.8-16sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-build-2.6.8-4-power3", ver:"2.6.8-13sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-build-2.6.8-4-power3-smp", ver:"2.6.8-13sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-build-2.6.8-4-power4", ver:"2.6.8-13sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-build-2.6.8-4-power4-smp", ver:"2.6.8-13sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-build-2.6.8-4-powerpc", ver:"2.6.8-13sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-build-2.6.8-4-powerpc-smp", ver:"2.6.8-13sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-doc-2.6.8", ver:"2.6.8-17sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-headers-2.6-itanium", ver:"2.6.8-15sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-headers-2.6-itanium-smp", ver:"2.6.8-15sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-headers-2.6-mckinley", ver:"2.6.8-15sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-headers-2.6-mckinley-smp", ver:"2.6.8-15sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-headers-2.6.8-13", ver:"2.6.8-17sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-headers-2.6.8-13-amd64-generic", ver:"2.6.8-17sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-headers-2.6.8-13-amd64-k8", ver:"2.6.8-17sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-headers-2.6.8-13-amd64-k8-smp", ver:"2.6.8-17sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-headers-2.6.8-13-em64t-p4", ver:"2.6.8-17sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-headers-2.6.8-13-em64t-p4-smp", ver:"2.6.8-17sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-headers-2.6.8-4", ver:"2.6.8-13sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-headers-2.6.8-4", ver:"2.6.8-15sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-headers-2.6.8-4", ver:"2.6.8-16sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-headers-2.6.8-4", ver:"2.6.8-17sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-headers-2.6.8-4", ver:"2.6.8-6sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-headers-2.6.8-4", ver:"2.6.8-7sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-headers-2.6.8-4-32", ver:"2.6.8-7sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-headers-2.6.8-4-32-smp", ver:"2.6.8-7sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-headers-2.6.8-4-386", ver:"2.6.8-17sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-headers-2.6.8-4-64", ver:"2.6.8-7sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-headers-2.6.8-4-64-smp", ver:"2.6.8-7sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-headers-2.6.8-4-686", ver:"2.6.8-17sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-headers-2.6.8-4-686-smp", ver:"2.6.8-17sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-headers-2.6.8-4-generic", ver:"2.6.8-17sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-headers-2.6.8-4-itanium", ver:"2.6.8-15sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-headers-2.6.8-4-itanium-smp", ver:"2.6.8-15sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-headers-2.6.8-4-k7", ver:"2.6.8-17sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-headers-2.6.8-4-k7-smp", ver:"2.6.8-17sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-headers-2.6.8-4-mckinley", ver:"2.6.8-15sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-headers-2.6.8-4-mckinley-smp", ver:"2.6.8-15sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-headers-2.6.8-4-smp", ver:"2.6.8-17sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-headers-2.6.8-4-sparc32", ver:"2.6.8-16sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-headers-2.6.8-4-sparc64", ver:"2.6.8-16sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-headers-2.6.8-4-sparc64-smp", ver:"2.6.8-16sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-2.6-itanium", ver:"2.6.8-15sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-2.6-itanium-smp", ver:"2.6.8-15sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-2.6-mckinley", ver:"2.6.8-15sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-2.6-mckinley-smp", ver:"2.6.8-15sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-2.6.8-13-amd64-generic", ver:"2.6.8-17sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-2.6.8-13-amd64-k8", ver:"2.6.8-17sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-2.6.8-13-amd64-k8-smp", ver:"2.6.8-17sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-2.6.8-13-em64t-p4", ver:"2.6.8-17sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-2.6.8-13-em64t-p4-smp", ver:"2.6.8-17sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-2.6.8-4-32", ver:"2.6.8-7sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-2.6.8-4-32-smp", ver:"2.6.8-7sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-2.6.8-4-386", ver:"2.6.8-17sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-2.6.8-4-64", ver:"2.6.8-7sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-2.6.8-4-64-smp", ver:"2.6.8-7sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-2.6.8-4-686", ver:"2.6.8-17sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-2.6.8-4-686-smp", ver:"2.6.8-17sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-2.6.8-4-generic", ver:"2.6.8-17sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-2.6.8-4-itanium", ver:"2.6.8-15sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-2.6.8-4-itanium-smp", ver:"2.6.8-15sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-2.6.8-4-k7", ver:"2.6.8-17sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-2.6.8-4-k7-smp", ver:"2.6.8-17sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-2.6.8-4-mckinley", ver:"2.6.8-15sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-2.6.8-4-mckinley-smp", ver:"2.6.8-15sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-2.6.8-4-power3", ver:"2.6.8-13sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-2.6.8-4-power3-smp", ver:"2.6.8-13sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-2.6.8-4-power4", ver:"2.6.8-13sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-2.6.8-4-power4-smp", ver:"2.6.8-13sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-2.6.8-4-powerpc", ver:"2.6.8-13sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-2.6.8-4-powerpc-smp", ver:"2.6.8-13sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-2.6.8-4-s390", ver:"2.6.8-6sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-2.6.8-4-s390-tape", ver:"2.6.8-6sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-2.6.8-4-s390x", ver:"2.6.8-6sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-2.6.8-4-smp", ver:"2.6.8-17sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-2.6.8-4-sparc32", ver:"2.6.8-16sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-2.6.8-4-sparc64", ver:"2.6.8-16sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-2.6.8-4-sparc64-smp", ver:"2.6.8-16sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-2.6.8-amiga", ver:"2.6.8-5sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-2.6.8-atari", ver:"2.6.8-5sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-2.6.8-bvme6000", ver:"2.6.8-5sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-2.6.8-hp", ver:"2.6.8-5sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-2.6.8-mac", ver:"2.6.8-5sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-2.6.8-mvme147", ver:"2.6.8-5sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-2.6.8-mvme16x", ver:"2.6.8-5sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-2.6.8-q40", ver:"2.6.8-5sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-2.6.8-sun3", ver:"2.6.8-5sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-patch-2.6.8-s390", ver:"2.6.8-6sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-patch-debian-2.6.8", ver:"2.6.8-17sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-source-2.6.8", ver:"2.6.8-17sarge1", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-tree-2.6.8", ver:"2.6.8-17sarge1", rls:"DEB3.1"))) {
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
