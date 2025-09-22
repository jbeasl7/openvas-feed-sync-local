# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.52641");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("FreeBSD Security Advisory (FreeBSD-SA-03:18.openssl.asc)");
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

This advisory addresses four separate flaws recently fixed in OpenSSL.
The flaws are described in the following excerpt from the OpenSSL.org
advisory (see references):

  1. Certain ASN.1 encodings that are rejected as invalid by the
  parser can trigger a bug in the deallocation of the corresponding
  data structure, corrupting the stack. This can be used as a denial
  of service attack. It is currently unknown whether this can be
  exploited to run malicious code. This issue does not affect OpenSSL
  0.9.6.

  2. Unusual ASN.1 tag values can cause an out of bounds read
  under certain circumstances, resulting in a denial of service
  vulnerability.

  3. A malformed public key in a certificate will crash the verify
  code if it is set to ignore public key decoding errors. Public
  key decode errors are not normally ignored, except for
  debugging purposes, so this is unlikely to affect production
  code. Exploitation of an affected application would result in a
  denial of service vulnerability.

  4. Due to an error in the SSL/TLS protocol handling, a server
  will parse a client certificate when one is not specifically
  requested. This by itself is not strictly speaking a vulnerability
  but it does mean that *all* SSL/TLS servers that use OpenSSL can be
  attacked using vulnerabilities 1, 2 and 3 even if they don't enable
  client authentication.");

  script_tag(name:"solution", value:"Upgrade your system to the appropriate stable release
  or security branch dated after the correction date.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FreeBSD-SA-03:18.openssl.asc");

  script_tag(name:"summary", value:"The remote host is missing an update to the system
  as announced in the referenced advisory FreeBSD-SA-03:18.openssl.asc");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-bsd.inc");

vuln = FALSE;

if(patchlevelcmp(rel:"5.1", patchlevel:"10")<0) {
  vuln = TRUE;
}
if(patchlevelcmp(rel:"5.0", patchlevel:"18")<0) {
  vuln = TRUE;
}
if(patchlevelcmp(rel:"4.8", patchlevel:"13")<0) {
  vuln = TRUE;
}
if(patchlevelcmp(rel:"4.7", patchlevel:"23")<0) {
  vuln = TRUE;
}
if(patchlevelcmp(rel:"4.6.2", patchlevel:"26")<0) {
  vuln = TRUE;
}

if(vuln) {
  security_message(port:0);
} else if (__pkg_match) {
  exit(99);
}