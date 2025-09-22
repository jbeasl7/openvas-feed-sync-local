# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.57326");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2006-4339");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_name("FreeBSD Security Advisory (FreeBSD-SA-06:19.openssl.asc)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdpatchlevel");

  script_tag(name:"insight", value:"FreeBSD includes software from the OpenSSL Project.  The OpenSSL Project is
a collaborative effort to develop a robust, commercial-grade, full-featured,
and Open Source toolkit implementing the Secure Sockets Layer (SSL v2/v3)
and Transport Layer Security (TLS v1) protocols as well as a full-strength
general purpose cryptography library.

PKCS#1 v1.5 is a standard for padding data before performing a
cryptographic operation using the RSA algorithm.  PKCS#1 v1.5 signatures
are for example used in X.509 certificates.

RSA public keys may use a variety of public exponents, of which 3, 17, and
65537 are most common.  As a result of a number of known attacks, most keys
generated recently use a public exponent of at least 65537.

When verifying a PKCS#1 v1.5 signature, OpenSSL ignores any bytes which
follow the cryptographic hash being signed.  In a valid signature there
will be no such bytes.");

  script_tag(name:"solution", value:"Upgrade your system to the appropriate stable release
  or security branch dated after the correction date.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FreeBSD-SA-06:19.openssl.asc");

  script_tag(name:"summary", value:"The remote host is missing an update to the system
  as announced in the referenced advisory FreeBSD-SA-06:19.openssl.asc");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-bsd.inc");

vuln = FALSE;

if(patchlevelcmp(rel:"6.1", patchlevel:"6")<0) {
  vuln = TRUE;
}
if(patchlevelcmp(rel:"6.0", patchlevel:"11")<0) {
  vuln = TRUE;
}
if(patchlevelcmp(rel:"5.5", patchlevel:"4")<0) {
  vuln = TRUE;
}
if(patchlevelcmp(rel:"5.4", patchlevel:"18")<0) {
  vuln = TRUE;
}
if(patchlevelcmp(rel:"5.3", patchlevel:"33")<0) {
  vuln = TRUE;
}
if(patchlevelcmp(rel:"4.11", patchlevel:"21")<0) {
  vuln = TRUE;
}

if(vuln) {
  security_message(port:0);
} else if (__pkg_match) {
  exit(99);
}