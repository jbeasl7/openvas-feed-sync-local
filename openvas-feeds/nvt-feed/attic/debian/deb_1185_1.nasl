# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.57478");
  script_version("2025-01-17T05:37:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 05:37:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2008-01-17 23:13:11 +0100 (Thu, 17 Jan 2008)");
  script_cve_id("CVE-2006-2940", "CVE-2006-3738", "CVE-2006-4343", "CVE-2006-2937");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Debian Security Advisory DSA 1185-1 (openssl)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_tag(name:"solution", value:"For the stable distribution (sarge) these problems have been fixed in
version 0.9.7e-3sarge3.

For the unstable and testing distributions (sid and etch,
respectively), these problems will be fixed in version 0.9.7k-2 of the
openssl097 compatibility libraries, and version 0.9.8c-2 of the
openssl package.

  We recommend that you upgrade your openssl package.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201185-1");
  script_tag(name:"summary", value:"The remote host is missing an update to openssl announced via advisory DSA 1185-1.  Multiple vulnerabilities have been discovered in the OpenSSL cryptographic software package that could allow an attacker to launch a denial of service attack by exhausting system resources or crashing processes on a victim's computer.  CVE-2006-2937 Dr S N Henson of the OpenSSL core team and Open Network Security recently developed an ASN1 test suite for NISCC. When the test suite was run against OpenSSL two denial of service vulnerabilities were discovered.  During the parsing of certain invalid ASN1 structures an error condition is mishandled. This can result in an infinite loop which consumes system memory.  Any code which uses OpenSSL to parse ASN1 data from untrusted sources is affected. This includes SSL servers which enable client authentication and S/MIME applications.  CVE-2006-3738 Tavis Ormandy and Will Drewry of the Google Security Team discovered a buffer overflow in SSL_get_shared_ciphers utility function, used by some applications such as exim and mysql.  An attacker could send a list of ciphers that would overrun a buffer.  CVE-2006-4343 Tavis Ormandy and Will Drewry of the Google Security Team discovered a possible DoS in the sslv2 client code.  Where a client application uses OpenSSL to make a SSLv2 connection to a malicious server that server could cause the client to crash.  CVE-2006-2940 Dr S N Henson of the OpenSSL core team and Open Network Security recently developed an ASN1 test suite for NISCC. When the test suite was run against OpenSSL a DoS was discovered.  Certain types of public key can take disproportionate amounts of time to process. This could be used by an attacker in a denial of service attack.

  This VT has been deprecated and merged into the VT 'Debian: Security Advisory (DSA-1185)' (OID: 1.3.6.1.4.1.25623.1.0.57481).");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
