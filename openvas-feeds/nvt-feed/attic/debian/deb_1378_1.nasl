# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.58636");
  script_version("2025-01-17T05:37:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 05:37:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2008-01-17 23:19:52 +0100 (Thu, 17 Jan 2008)");
  script_cve_id("CVE-2007-3731", "CVE-2007-3739", "CVE-2007-3740", "CVE-2007-4573", "CVE-2007-4849");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Debian Security Advisory DSA 1378-1 (linux-2.6)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201378-1");
  script_tag(name:"insight", value:"Several local and remote vulnerabilities have been discovered in the Linux
kernel that may lead to a denial of service or the execution of arbitrary
code. The Common Vulnerabilities and Exposures project identifies the
following problems:

CVE-2007-3731

Evan Teran discovered a potential local denial of service (oops) in
the handling of PTRACE_SETREGS and PTRACE_SINGLESTEP requests.

CVE-2007-3739

Adam Litke reported a potential local denial of service (oops) on
powerpc platforms resulting from unchecked VMA expansion into address
space reserved for hugetlb pages.

CVE-2007-3740

Steve French reported that CIFS filesystems with CAP_UNIX enabled
were not honoring a process's umask which may lead to unintentinally
relaxed permissions.

CVE-2007-4573

Wojciech Purczynski discovered a vulnerability that can be exploitd
by a local user to obtain superuser privileges on x86_64 systems.
This resulted from improper clearing of the high bits of registers
during ia32 system call emulation. This vulnerability is relevant
to the Debian amd64 port as well as users of the i386 port who run
the amd64 linux-image flavour.

CVE-2007-4849

Michael Stone reported an issue with the JFFS2 filesystem. Legacy
modes for inodes that were created with POSIX ACL support enabled
were not being written out to the medium, resulting in incorrect
permissions upon remount.

These problems have been fixed in the stable distribution in version
2.6.18.dfsg.1-13etch3.

At the time of this advisory, the build for the arm architecture has
not yet completed. This advisory will be updated once the arm build
is available.

The following matrix lists additional packages that were rebuilt for
compatibility with or to take advantage of this update:

Debian 4.0 (etch)
fai-kernels                 1.17+etch.13etch3
user-mode-linux             2.6.18-1um-2etch.13etch3");

  script_tag(name:"solution", value:"We recommend that you upgrade your kernel package immediately and reboot");
  script_tag(name:"summary", value:"The remote host is missing an update to linux-2.6 announced via advisory DSA 1378-1.

  This VT has been deprecated and merged into the VT 'Debian: Security Advisory (DSA-1378)' (OID: 1.3.6.1.4.1.25623.1.0.58637).");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
