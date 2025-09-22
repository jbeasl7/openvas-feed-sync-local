# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.52659");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2004-1066");
  script_tag(name:"cvss_base", value:"3.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:P");
  script_name("FreeBSD Security Advisory (FreeBSD-SA-04:17.procfs.asc)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdpatchlevel");

  script_tag(name:"insight", value:"The process file system, procfs(5), implements a view of the system
process table inside the file system.  It is normally mounted on
/proc, and is required for the complete operation of programs such as
ps(1) and w(1).

The Linux process file system, linprocfs(5), emulates a subset of
Linux's process file system and is required for the complete operation
of some Linux binaries.

The implementation of the /proc/curproc/cmdline pseudofile in the procfs(5)
file system on FreeBSD 4.x and 5.x, and of the /proc/self/cmdline
pseudofile in the linprocfs(5) file system on FreeBSD 5.x reads a process'
argument vector from the process address space.  During this operation,
a pointer was dereferenced directly without the necessary validation
steps being performed.");

  script_tag(name:"solution", value:"Upgrade your system to the appropriate stable release
  or security branch dated after the correction date.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FreeBSD-SA-04:17.procfs.asc");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/11789");

  script_tag(name:"summary", value:"The remote host is missing an update to the system
  as announced in the referenced advisory FreeBSD-SA-04:17.procfs.asc");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-bsd.inc");

vuln = FALSE;

if(patchlevelcmp(rel:"5.3", patchlevel:"2")<0) {
  vuln = TRUE;
}
if(patchlevelcmp(rel:"5.2.1", patchlevel:"13")<0) {
  vuln = TRUE;
}
if(patchlevelcmp(rel:"4.10", patchlevel:"5")<0) {
  vuln = TRUE;
}
if(patchlevelcmp(rel:"4.8", patchlevel:"27")<0) {
  vuln = TRUE;
}

if(vuln) {
  security_message(port:0);
} else if (__pkg_match) {
  exit(99);
}