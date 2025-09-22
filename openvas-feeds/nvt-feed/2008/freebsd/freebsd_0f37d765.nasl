# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.58053");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2006-2937", "CVE-2006-2940", "CVE-2006-3738", "CVE-2006-4343");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("FreeBSD Ports: openssl");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsdrel", "login/SSH/success");

  script_xref(name:"URL", value:"https://www.vuxml.org/freebsd/0f37d765-c5d4-11db-9f82-000e0c2e438a.html");
  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_tag(name:"insight", value:"The following package is affected: openssl

  CVE-2006-2937 OpenSSL 0.9.7 before 0.9.7l and 0.9.8 before 0.9.8d allows remote
  attackers to cause a denial of service (infinite loop and memory
  consumption) via malformed ASN.1 structures that trigger an improperly
  handled error condition.

  CVE-2006-2940 OpenSSL 0.9.7 before 0.9.7l, 0.9.8 before 0.9.8d, and earlier versions
  allows attackers to cause a denial of service (CPU consumption) via
  parasitic public keys with large (1) 'public exponent' or (2) 'public
  modulus' values in X.509 certificates that require extra time to
  process when using RSA signature verification.

  CVE-2006-3738 Buffer overflow in the SSL_get_shared_ciphers function in OpenSSL
  0.9.7 before 0.9.7l, 0.9.8 before 0.9.8d, and earlier versions has
  unspecified impact and remote attack vectors involving a long list of
  ciphers.

  CVE-2006-4343 The get_server_hello function in the SSLv2 client code in OpenSSL
  0.9.7 before 0.9.7l, 0.9.8 before 0.9.8d, and earlier versions allows
  remote servers to cause a denial of service (client crash) via unknown
  vectors that trigger a null pointer dereference.");

  script_tag(name:"summary", value:"The remote host is missing an update to the system
  as announced in the referenced advisory.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-bsd.inc");
include("revisions-lib.inc");

txt = "";
vuln = 0;
bver = portver(pkg:"openssl");
if(!isnull(bver) && revcomp(a:bver, b:"0.9.7l_0")<0) {
  txt += 'Package openssl version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"0.9.8")>0 && revcomp(a:bver, b:"0.9.8d_0")<0) {
  txt += 'Package openssl version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}
