# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.52651");
  script_version("2024-02-05T05:05:38+0000");
  script_tag(name:"last_modification", value:"2024-02-05 05:05:38 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2004-0434");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-02 03:05:48 +0000 (Fri, 02 Feb 2024)");
  script_name("FreeBSD Security Advisory (FreeBSD-SA-04:09.kadmind.asc)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdpatchlevel");

  script_tag(name:"insight", value:"Heimdal implements the Kerberos 5 network authentication protocols.
The k5admind(8) daemon provides the administrative interface to the
Kerberos Key Distribution Center (KDC).  In some configurations,
k5admind also includes Kerberos 4 compatibility.

NOTE: FreeBSD versions prior to 5.1-RELEASE contain optional Kerberos
4 support.  FreeBSD versions 5.1-RELEASE and later do not include
Kerberos 4 support of any kind.

An input validation error was discovered in the k5admind code that
handles the framing of Kerberos 4 compatibility administration
requests.  The code assumed that the length given in the framing was
always two or more bytes.  Smaller lengths will cause k5admind to read
an arbitrary amount of data into a minimally-sized buffer on the heap.

Note that this code is not present unless k5admind has been compiled
with Kerberos 4 support.  This will occur if a FreeBSD system is
compiled with both of the WITH_KERBEROS4 and WITH_KERBEROS5 build flags.
These flags are never simultaneously set during the FreeBSD binary
release process. Consequently, binary installs of FreeBSD (even with
Kerberos support installed) are not affected.");

  script_tag(name:"solution", value:"Upgrade your system to the appropriate stable release
  or security branch dated after the correction date.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FreeBSD-SA-04:09.kadmind.asc");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/10288");

  script_tag(name:"summary", value:"The remote host is missing an update to the system
  as announced in the referenced advisory FreeBSD-SA-04:09.kadmind.asc");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-bsd.inc");

vuln = FALSE;

if(patchlevelcmp(rel:"4.9", patchlevel:"7")<0) {
  vuln = TRUE;
}
if(patchlevelcmp(rel:"4.8", patchlevel:"20")<0) {
  vuln = TRUE;
}

if(vuln) {
  security_message(port:0);
} else if (__pkg_match) {
  exit(99);
}