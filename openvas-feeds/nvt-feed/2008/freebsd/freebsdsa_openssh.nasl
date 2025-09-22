# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.52635");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2003-0693");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("FreeBSD Security Advisory (FreeBSD-SA-03:12.openssh.asc)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdpatchlevel");

  script_tag(name:"insight", value:"OpenSSH is a free version of the SSH protocol suite of network
connectivity tools.  OpenSSH encrypts all traffic (including
passwords) to effectively eliminate eavesdropping, connection
hijacking, and other network-level attacks. Additionally, OpenSSH
provides a myriad of secure tunneling capabilities, as well as a
variety of authentication methods. `ssh' is the client application,
while `sshd' is the server.

Several operations within OpenSSH require dynamic memory allocation
or reallocation.  Examples are: the receipt of a packet larger
than available space in a currently allocated buffer. Creation of
additional channels beyond the currently allocated maximum, and
allocation of new sockets beyond the currently allocated maximum.
Many of these operations can fail either due to `out of memory' or
due to explicit checks for ridiculously sized requests.  However, the
failure occurs after the allocation size has already been updated, so
that the bookkeeping data structures are in an inconsistent state (the
recorded size is larger than the actual allocation).  Furthermore,
the detection of these failures causes OpenSSH to invoke several
`fatal_cleanup' handlers, some of which may then attempt to use these
inconsistent data structures.  For example, a handler may zero and
free a buffer in this state, and as a result memory outside of the
allocated area will be overwritten with NUL bytes.");

  script_tag(name:"solution", value:"Upgrade your system to the appropriate stable release
  or security branch dated after the correction date.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FreeBSD-SA-03:12.openssh.asc");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/8628");

  script_tag(name:"summary", value:"The remote host is missing an update to the system
  as announced in the referenced advisory FreeBSD-SA-03:12.openssh.asc");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-bsd.inc");

vuln = FALSE;

if(patchlevelcmp(rel:"5.1", patchlevel:"4")<0) {
  vuln = TRUE;
}
if(patchlevelcmp(rel:"5.0", patchlevel:"13")<0) {
  vuln = TRUE;
}
if(patchlevelcmp(rel:"4.8", patchlevel:"6")<0) {
  vuln = TRUE;
}
if(patchlevelcmp(rel:"4.7", patchlevel:"16")<0) {
  vuln = TRUE;
}
if(patchlevelcmp(rel:"4.6", patchlevel:"19")<0) {
  vuln = TRUE;
}
if(patchlevelcmp(rel:"4.5", patchlevel:"31")<0) {
  vuln = TRUE;
}
if(patchlevelcmp(rel:"4.4", patchlevel:"41")<0) {
  vuln = TRUE;
}
if(patchlevelcmp(rel:"4.3", patchlevel:"37")<0) {
  vuln = TRUE;
}

if(vuln) {
  security_message(port:0);
} else if (__pkg_match) {
  exit(99);
}