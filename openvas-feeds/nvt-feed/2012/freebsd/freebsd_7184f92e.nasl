# SPDX-FileCopyrightText: 2012 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.71273");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2012-2110");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-04-30 07:59:26 -0400 (Mon, 30 Apr 2012)");
  script_name("FreeBSD Ports: openssl");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following package is affected: openssl

CVE-2012-2110
The asn1_d2i_read_bio function in crypto/asn1/a_d2i_fp.c in OpenSSL
before 0.9.8v, 1.0.0 before 1.0.0i, and 1.0.1 before 1.0.1a does not
properly interpret integer data, which allows remote attackers to
conduct buffer overflow attacks, and cause a denial of service (memory
corruption) or possibly have unspecified other impact, via crafted DER
data, as demonstrated by an X.509 certificate or an RSA public key.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://www.openssl.org/news/secadv_20120419.txt");
  script_xref(name:"URL", value:"http://marc.info/?l=full-disclosure&m=133483221408243");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/7184f92e-8bb8-11e1-8d7b-003067b2972c.html");

  script_tag(name:"summary", value:"The remote host is missing an update to the system
  as announced in the referenced advisory.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-bsd.inc");

vuln = FALSE;
txt = "";

bver = portver(pkg:"openssl");
if(!isnull(bver) && revcomp(a:bver, b:"1.0.1_1")<0) {
  txt += "Package openssl version " + bver + " is installed which is known to be vulnerable.\n";
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}