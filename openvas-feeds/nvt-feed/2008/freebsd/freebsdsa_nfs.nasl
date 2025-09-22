# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.56353");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2006-0900");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_name("FreeBSD Security Advisory (FreeBSD-SA-06:10.nfs.asc)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdpatchlevel");

  script_tag(name:"insight", value:"The Network File System (NFS) allows a host to export some or all of
its filesystems so that other hosts can access them over the network
and mount them as if they were on local disks.  NFS is built on top of
the Sun Remote Procedure Call (RPC) framework.

A part of the NFS server code charged with handling incoming RPC
messages via TCP had an error which, when the server received a
message with a zero-length payload, would cause a NULL pointer
dereference which results in a kernel panic.  The kernel will only
process the RPC messages if a userland nfsd daemon is running.");

  script_tag(name:"solution", value:"Upgrade your system to the appropriate stable release
  or security branch dated after the correction date.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FreeBSD-SA-06:10.nfs.asc");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/16838");

  script_tag(name:"summary", value:"The remote host is missing an update to the system
  as announced in the referenced advisory FreeBSD-SA-06:10.nfs.asc");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-bsd.inc");

vuln = FALSE;

if(patchlevelcmp(rel:"6.0", patchlevel:"5")<0) {
  vuln = TRUE;
}
if(patchlevelcmp(rel:"5.4", patchlevel:"12")<0) {
  vuln = TRUE;
}
if(patchlevelcmp(rel:"5.3", patchlevel:"27")<0) {
  vuln = TRUE;
}
if(patchlevelcmp(rel:"4.11", patchlevel:"15")<0) {
  vuln = TRUE;
}
if(patchlevelcmp(rel:"4.10", patchlevel:"21")<0) {
  vuln = TRUE;
}

if(vuln) {
  security_message(port:0);
} else if (__pkg_match) {
  exit(99);
}