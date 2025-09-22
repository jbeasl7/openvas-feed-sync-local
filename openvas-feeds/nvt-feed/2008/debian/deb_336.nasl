# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53625");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-01-17 22:36:24 +0100 (Thu, 17 Jan 2008)");
  script_cve_id("CVE-2002-0429", "CVE-2003-0001", "CVE-2003-0127", "CVE-2003-0244", "CVE-2003-0246", "CVE-2003-0247", "CVE-2003-0248", "CVE-2003-0364");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Debian Security Advisory DSA 336-1 (kernel-source-2.2.20, kernel-image-2.2.20-i386)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.0");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20336-1");
  script_tag(name:"insight", value:"A number of vulnerabilities have been discovered in the Linux kernel.

  - - CVE-2002-0429: The iBCS routines in arch/i386/kernel/traps.c for
Linux kernels 2.4.18 and earlier on x86 systems allow local users to
kill arbitrary processes via a binary compatibility interface
(lcall)

  - - CVE-2003-0001: Multiple ethernet Network Interface Card (NIC) device
drivers do not pad frames with null bytes, which allows remote
attackers to obtain information from previous packets or kernel
memory by using malformed packets

  - - CVE-2003-0127: The kernel module loader allows local users to gain
root privileges by using ptrace to attach to a child process that is
spawned by the kernel

  - - CVE-2003-0244: The route cache implementation in Linux 2.4, and the
Netfilter IP conntrack module, allows remote attackers to cause a
denial of service (CPU consumption) via packets with forged source
addresses that cause a large number of hash table collisions related
to the PREROUTING chain

  - - CVE-2003-0246: The ioperm system call in Linux kernel 2.4.20 and
earlier does not properly restrict privileges, which allows local
users to gain read or write access to certain I/O ports.

  - - CVE-2003-0247: vulnerability in the TTY layer of the Linux kernel
2.4 allows attackers to cause a denial of service ('kernel oops')

  - - CVE-2003-0248: The mxcsr code in Linux kernel 2.4 allows attackers
to modify CPU state registers via a malformed address.

  - - CVE-2003-0364: The TCP/IP fragment reassembly handling in the Linux
kernel 2.4 allows remote attackers to cause a denial of service (CPU
consumption) via certain packets that cause a large number of hash
table collisions

This advisory provides updated 2.2.20 kernel source, and binary kernel
images for the i386 architecture.  Other architectures and kernel
versions will be covered by separate advisories.");

  script_tag(name:"solution", value:"For the stable distribution (woody) on the powerpc architecture, these
problems have been fixed in kernel-source-2.2.20 version
2.2.20-5woody2 and kernel-image-i386 version 2.2.20-5woody3.

For the unstable distribution (sid) these problems are fixed in
kernel-source-2.2.25 and kernel-image-2.2.25-i386 version 2.2.25-2.

We recommend that you update your kernel packages.

NOTE: A system reboot will be required immediately after the upgrade
in order to replace the running kernel.  Remember to read carefully
and follow the instructions given during the kernel upgrade process.

NOTE: These kernels are not binary-compatible with the previous
version.  Any loadable modules will need to be recompiled in order to
work with the new kernel.");
  script_tag(name:"summary", value:"The remote host is missing an update to kernel-source-2.2.20, kernel-image-2.2.20-i386
announced via advisory DSA 336-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"kernel-doc-2.2.20", ver:"2.2.20-5woody2", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kernel-source-2.2.20", ver:"2.2.20-5woody2", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kernel-headers-2.2.20", ver:"2.2.20-5woody3", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kernel-headers-2.2.20-compact", ver:"2.2.20-5woody3", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kernel-headers-2.2.20-idepci", ver:"2.2.20-5woody3", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kernel-image-2.2.20", ver:"2.2.20-5woody3", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kernel-image-2.2.20-compact", ver:"2.2.20-5woody3", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"kernel-image-2.2.20-idepci", ver:"2.2.20-5woody3", rls:"DEB3.0")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
