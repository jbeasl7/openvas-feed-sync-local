# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.52650");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2004-0371");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_name("FreeBSD Security Advisory (FreeBSD-SA-04:08.heimdal.asc)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdpatchlevel");

  script_tag(name:"insight", value:"Heimdal implements the Kerberos 5 network authentication protocols.
Principals (i.e. users and services) represented in Kerberos are
grouped into separate, autonomous realms.  Unidirectional or
bidirectional trust relationships may be established between realms to
allow the principals in one realm to recognize the authenticity of
principals in another.  These trust relationships may be transitive.
An authentication path is the ordered list of realms (and therefore
KDCs) that were involved in the authentication process.  The
authentication path is recorded in Kerberos tickets as the `transited'
field.

It is possible for the Key Distribution Center (KDC) of a realm to
forge part or all of the `transited' field.  KDCs should validate this
field before accepting authentication results, checking that each
realm in the authentication path is trusted and that the path conforms
to local policy.  Applications are required to perform this type of
checking if the KDC has not already done so.

Prior to FreeBSD 5.1, Kerberos 5 was an optional component of FreeBSD,
and was not installed by default.

Some versions of Heimdal do not perform appropriate checking of the
`transited' field.");

  script_tag(name:"solution", value:"Upgrade your system to the appropriate stable release
  or security branch dated after the correction date.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FreeBSD-SA-04:08.heimdal.asc");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/10035");

  script_tag(name:"summary", value:"The remote host is missing an update to the system
  as announced in the referenced advisory FreeBSD-SA-04:08.heimdal.asc");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-bsd.inc");

vuln = FALSE;

if(patchlevelcmp(rel:"5.2.1", patchlevel:"6")<0) {
  vuln = TRUE;
}
if(patchlevelcmp(rel:"4.9", patchlevel:"6")<0) {
  vuln = TRUE;
}
if(patchlevelcmp(rel:"4.8", patchlevel:"19")<0) {
  vuln = TRUE;
}

if(vuln) {
  security_message(port:0);
} else if (__pkg_match) {
  exit(99);
}