# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.55232");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2005-2693");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_name("FreeBSD Security Advisory (FreeBSD-SA-05:20.cvsbug.asc)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdpatchlevel");

  script_tag(name:"insight", value:"cvsbug(1) is a utility for reporting problems in the CVS revision
control system.  It is based on the GNATS send-pr(1) utility.

A temporary file is created, used, deleted, and then re-created with
the same name.  This creates a window during which an attacker could
replace the file with a link to another file.

While cvsbug(1) is based on the send-pr(1) utility, this problem does
not exist in the version of send-pr(1) distributed with FreeBSD.");

  script_tag(name:"solution", value:"Upgrade your system to the appropriate stable release
  or security branch dated after the correction date.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FreeBSD-SA-05:20.cvsbug.asc");

  script_tag(name:"summary", value:"The remote host is missing an update to the system
  as announced in the referenced advisory FreeBSD-SA-05:20.cvsbug.asc");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-bsd.inc");

vuln = FALSE;

if(patchlevelcmp(rel:"5.4", patchlevel:"7")<0) {
  vuln = TRUE;
}
if(patchlevelcmp(rel:"5.3", patchlevel:"21")<0) {
  vuln = TRUE;
}
if(patchlevelcmp(rel:"4.11", patchlevel:"12")<0) {
  vuln = TRUE;
}
if(patchlevelcmp(rel:"4.10", patchlevel:"17")<0) {
  vuln = TRUE;
}

if(vuln) {
  security_message(port:0);
} else if (__pkg_match) {
  exit(99);
}