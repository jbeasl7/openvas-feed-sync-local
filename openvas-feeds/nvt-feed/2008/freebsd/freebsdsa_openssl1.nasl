# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.52647");
  script_version("2024-01-01T05:05:52+0000");
  script_tag(name:"last_modification", value:"2024-01-01 05:05:52 +0000 (Mon, 01 Jan 2024)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2004-0079");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-28 15:33:00 +0000 (Thu, 28 Dec 2023)");
  script_name("FreeBSD Security Advisory (FreeBSD-SA-04:05.openssl.asc)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdpatchlevel");

  script_tag(name:"insight", value:"FreeBSD includes software from the OpenSSL Project.  The OpenSSL
Project is a collaborative effort to develop a robust, commercial-
grade, full-featured, and Open Source toolkit implementing the Secure
Sockets Layer (SSL v2/v3) and Transport Layer Security (TLS v1)
protocols as well as a full-strength general purpose cryptography
library.

When processing an SSL/TLS ChangeCipherSpec message, OpenSSL may fail to
check that a new cipher has been previously negotiated.  This may result
in a null pointer dereference.");

  script_tag(name:"solution", value:"Upgrade your system to the appropriate stable release
  or security branch dated after the correction date.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FreeBSD-SA-04:05.openssl.asc");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/9899");

  script_tag(name:"summary", value:"The remote host is missing an update to the system
  as announced in the referenced advisory FreeBSD-SA-04:05.openssl.asc");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-bsd.inc");

vuln = FALSE;

if(patchlevelcmp(rel:"5.2.1", patchlevel:"3")<0) {
  vuln = TRUE;
}
if(patchlevelcmp(rel:"5.1", patchlevel:"16")<0) {
  vuln = TRUE;
}
if(patchlevelcmp(rel:"4.9", patchlevel:"4")<0) {
  vuln = TRUE;
}
if(patchlevelcmp(rel:"4.8", patchlevel:"17")<0) {
  vuln = TRUE;
}

if(vuln) {
  security_message(port:0);
} else if (__pkg_match) {
  exit(99);
}