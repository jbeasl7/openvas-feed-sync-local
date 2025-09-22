# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.52656");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2004-0414", "CVE-2004-0778");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("FreeBSD Security Advisory (FreeBSD-SA-04:14.cvs.asc)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdpatchlevel");

  script_tag(name:"insight", value:"The Concurrent Versions System (CVS) is a version control system.  It
may be used to access a repository locally, or to access a `remote
repository' using a number of different methods.  When accessing a
remote repository, the target machine runs the CVS server to fulfill
client requests.

A number of vulnerabilities were discovered in CVS by Stefan Esser,
Sebastian Krahmer, and Derek Price.

 . Insufficient input validation while processing Entry lines.
   (CVE-2004-0414)

 . A double-free resulting from erroneous state handling while
   processing Argumentx commands. (CVE-2004-0416)

 . Integer overflow while processing Max-dotdot commands.
   (CVE-2004-0417)

 . Erroneous handling of empty entries handled while processing
   Notify commands. (CVE-2004-0418)

 . A format string bug while processing CVS wrappers.

 . Single-byte buffer underflows while processing configuration files
   from CVSROOT.

 . Various other integer overflows.

Additionally, iDEFENSE reports an undocumented command-line flag used
in debugging does not perform input validation on the given path
names.");

  script_tag(name:"solution", value:"Upgrade your system to the appropriate stable release
  or security branch dated after the correction date.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FreeBSD-SA-04:14.cvs.asc");

  script_tag(name:"summary", value:"The remote host is missing an update to the system
  as announced in the referenced advisory FreeBSD-SA-04:14.cvs.asc");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-bsd.inc");

vuln = FALSE;

if(patchlevelcmp(rel:"4.10", patchlevel:"3")<0) {
  vuln = TRUE;
}
if(patchlevelcmp(rel:"4.9", patchlevel:"12")<0) {
  vuln = TRUE;
}
if(patchlevelcmp(rel:"4.8", patchlevel:"25")<0) {
  vuln = TRUE;
}
if(patchlevelcmp(rel:"5.2.1", patchlevel:"10")<0) {
  vuln = TRUE;
}

if(vuln) {
  security_message(port:0);
} else if (__pkg_match) {
  exit(99);
}