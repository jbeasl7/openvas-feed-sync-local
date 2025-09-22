# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.61516");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2008-3890");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_name("FreeBSD Security Advisory (FreeBSD-SA-08:07.amd64.asc)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdpatchlevel");

  script_tag(name:"insight", value:"FreeBSD/amd64 is commonly used on 64bit systems with AMD and Intel
CPU's.  For Intel CPU's this architecture is known as EM64T or Intel 64.

The gs segment CPU register is used by both user processes and the
kernel to conveniently access state data.  User processes use it to
manage per-thread data, and the kernel uses it to manage per-processor
data.  As the processor enters and leaves the kernel it uses the
'swapgs' instruction to toggle between the kernel and user values for
the gs register.

The kernel stores critical information in its per-processor data
block.  This includes the currently executing process and its
credentials.

As the processor switches between user and kernel level, a number of
checks are performed in order to implement the privilege protection
system.  If the processor detects a problem while attempting to switch
privilege levels it generates a trap - typically general protection
fault (GPF).  In that case, the processor aborts the return to the
user level process and re-enters the kernel.  The FreeBSD kernel
allows the user process to be notified of such an event by a signal
(SIGSEGV or SIGBUS).

If a General Protection Fault happens on a FreeBSD/amd64 system while
it is returning from an interrupt, trap or system call, the swapgs CPU
instruction may be called one extra time when it should not resulting
in userland and kernel state being mixed.");

  script_tag(name:"solution", value:"Upgrade your system to the appropriate stable release
  or security branch dated after the correction date.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FreeBSD-SA-08:07.amd64.asc");

  script_tag(name:"summary", value:"The remote host is missing an update to the system
  as announced in the referenced advisory FreeBSD-SA-08:07.amd64.asc");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-bsd.inc");

vuln = FALSE;

if(patchlevelcmp(rel:"7.0", patchlevel:"4")<0) {
  vuln = TRUE;
}
if(patchlevelcmp(rel:"6.3", patchlevel:"4")<0) {
  vuln = TRUE;
}

if(vuln) {
  security_message(port:0);
} else if (__pkg_match) {
  exit(99);
}