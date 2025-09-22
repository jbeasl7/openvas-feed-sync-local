# SPDX-FileCopyrightText: 2010 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.66663");
  script_version("2023-07-26T05:05:09+0000");
  script_cve_id("CVE-2010-0318");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-01-11 23:48:26 +0100 (Mon, 11 Jan 2010)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_name("FreeBSD Security Advisory (FreeBSD-SA-10:03.zfs.asc)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdpatchlevel");

  script_tag(name:"insight", value:"ZFS is a file-system originally developed by Sun Microsystems.

The ZFS Intent Log (ZIL) is a mechanism that gathers together in memory
transactions of writes, and is flushed onto disk when synchronous
semantics is necessary.  In the event of crash or power failure, the
log is examined and the uncommitted transaction would be replayed to
maintain the synchronous semantics.

When replaying setattr transaction, the replay code would set the
attributes with certain insecure defaults, when the logged
transaction did not touch these attributes.");

  script_tag(name:"solution", value:"Upgrade your system to the appropriate stable release
  or security branch dated after the correction date.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FreeBSD-SA-10:03.zfs.asc");

  script_tag(name:"summary", value:"The remote host is missing an update to the system
  as announced in the referenced advisory FreeBSD-SA-10:03.zfs.asc");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-bsd.inc");

vuln = FALSE;

if(patchlevelcmp(rel:"8.0", patchlevel:"2")<0) {
  vuln = TRUE;
}
if(patchlevelcmp(rel:"7.2", patchlevel:"6")<0) {
  vuln = TRUE;
}
if(patchlevelcmp(rel:"7.1", patchlevel:"10")<0) {
  vuln = TRUE;
}

if(vuln) {
  security_message(port:0);
} else if (__pkg_match) {
  exit(99);
}