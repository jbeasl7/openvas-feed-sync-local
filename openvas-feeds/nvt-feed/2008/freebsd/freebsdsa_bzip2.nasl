# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53975");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2005-0953");
  script_tag(name:"cvss_base", value:"3.7");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:P/I:P/A:P");
  script_name("FreeBSD Security Advisory (FreeBSD-SA-05:14.bzip2.asc)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdpatchlevel");

  script_tag(name:"insight", value:"bzip2 is a block-sorting file compression utility.

Two problems have been discovered relating to the extraction of
bzip2-compressed files.  First, a carefully constructed invalid bzip2
archive can cause bzip2 to enter an infinite loop.  Second, when
creating a new file, bzip2 closes the file before setting its
permissions.");

  script_tag(name:"solution", value:"Upgrade your system to the appropriate stable release
  or security branch dated after the correction date.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FreeBSD-SA-05:14.bzip2.asc");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/12954");

  script_tag(name:"summary", value:"The remote host is missing an update to the system
  as announced in the referenced advisory FreeBSD-SA-05:14.bzip2.asc");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-bsd.inc");

vuln = FALSE;

if(patchlevelcmp(rel:"5.4", patchlevel:"3")<0) {
  vuln = TRUE;
}
if(patchlevelcmp(rel:"5.3", patchlevel:"17")<0) {
  vuln = TRUE;
}
if(patchlevelcmp(rel:"4.11", patchlevel:"11")<0) {
  vuln = TRUE;
}
if(patchlevelcmp(rel:"4.10", patchlevel:"16")<0) {
  vuln = TRUE;
}

if(vuln) {
  security_message(port:0);
} else if (__pkg_match) {
  exit(99);
}