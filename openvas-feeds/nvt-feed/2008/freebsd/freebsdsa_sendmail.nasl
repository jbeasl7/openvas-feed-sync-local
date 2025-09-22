# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.52636");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("FreeBSD Security Advisory (FreeBSD-SA-03:13.sendmail.asc)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdpatchlevel");

  script_tag(name:"insight", value:"FreeBSD includes sendmail(8), a general purpose internetwork mail
routing facility, as the default Mail Transfer Agent (MTA).

A buffer overflow that may occur during header parsing was identified.

NOTE WELL:  This issue is distinct from the issue described in
`FreeBSD-SA-03:04.sendmail' and `FreeBSD-SA-03:07.sendmail', although
the impact is very similar.");

  script_tag(name:"solution", value:"Upgrade your system to the appropriate stable release
  or security branch dated after the correction date.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FreeBSD-SA-03:13.sendmail.asc");

  script_tag(name:"summary", value:"The remote host is missing an update to the system
  as announced in the referenced advisory FreeBSD-SA-03:13.sendmail.asc");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-bsd.inc");

vuln = FALSE;

if(patchlevelcmp(rel:"5.1", patchlevel:"5")<0) {
  vuln = TRUE;
}
if(patchlevelcmp(rel:"5.0", patchlevel:"14")<0) {
  vuln = TRUE;
}
if(patchlevelcmp(rel:"4.8", patchlevel:"7")<0) {
  vuln = TRUE;
}
if(patchlevelcmp(rel:"4.7", patchlevel:"17")<0) {
  vuln = TRUE;
}
if(patchlevelcmp(rel:"4.6", patchlevel:"20")<0) {
  vuln = TRUE;
}
if(patchlevelcmp(rel:"4.5", patchlevel:"32")<0) {
  vuln = TRUE;
}
if(patchlevelcmp(rel:"4.4", patchlevel:"42")<0) {
  vuln = TRUE;
}
if(patchlevelcmp(rel:"4.3", patchlevel:"38")<0) {
  vuln = TRUE;
}

if(vuln) {
  security_message(port:0);
} else if (__pkg_match) {
  exit(99);
}