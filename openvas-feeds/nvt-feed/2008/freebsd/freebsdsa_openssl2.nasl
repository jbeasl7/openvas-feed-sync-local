# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.55572");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2005-2969");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_name("FreeBSD Security Advisory (FreeBSD-SA-05:21.openssl.asc)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdpatchlevel");

  script_tag(name:"insight", value:"The OpenSSL library implements the Secure Sockets Layer and Transport
Layer Security protocols, as well as providing a large number of basic
cryptographic functions.

The Secure Sockets Layer protocol exists in two versions and includes a
mechanism for negotiating the protocol version to be used.  If the
protocol is executed correctly, it is impossible for a client and
server both capable of the newer version of the protocol (SSLv3) to end
up using the older version of the protocol (SSLv2).

In order to provide bug-for-bug compatibility with Microsoft Internet
Explorer 3.02, a verification step required by the Secure Sockets Layer
protocol can be disabled by using the SSL_OP_MSIE_SSLV2_RSA_PADDING
option in OpenSSL.  This option is implied by the frequently-used
SSL_OP_ALL option.");

  script_tag(name:"solution", value:"Upgrade your system to the appropriate stable release
  or security branch dated after the correction date.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FreeBSD-SA-05:21.openssl.asc");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/15071");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/15647");

  script_tag(name:"summary", value:"The remote host is missing an update to the system
  as announced in the referenced advisory FreeBSD-SA-05:21.openssl.asc");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-bsd.inc");

vuln = FALSE;

if(patchlevelcmp(rel:"5.4", patchlevel:"8")<0) {
  vuln = TRUE;
}
if(patchlevelcmp(rel:"5.3", patchlevel:"23")<0) {
  vuln = TRUE;
}
if(patchlevelcmp(rel:"4.11", patchlevel:"13")<0) {
  vuln = TRUE;
}
if(patchlevelcmp(rel:"4.10", patchlevel:"19")<0) {
  vuln = TRUE;
}

if(vuln) {
  security_message(port:0);
} else if (__pkg_match) {
  exit(99);
}