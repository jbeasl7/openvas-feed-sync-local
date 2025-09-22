# SPDX-FileCopyrightText: 2012 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.70608");
  script_tag(name:"creation_date", value:"2012-02-13 01:48:16 +0100 (Mon, 13 Feb 2012)");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_cve_id("CVE-2011-4128");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_version("2023-07-26T05:05:09+0000");
  script_name("FreeBSD Ports: gnutls");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following package is affected: gnutls

CVE-2011-4128
Buffer overflow in the gnutls_session_get_data function in
lib/gnutls_session.c in GnuTLS 2.12.x before 2.12.14 and 3.x before
3.0.7, when used on a client that performs nonstandard session
resumption, allows remote TLS servers to cause a denial of service
(application crash) via a large SessionTicket.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://article.gmane.org/gmane.comp.encryption.gpg.gnutls.devel/5596");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/bdec8dc2-0b3b-11e1-b722-001cc0476564.html");

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

bver = portver(pkg:"gnutls");
if(!isnull(bver) && revcomp(a:bver, b:"2.12.14")<0) {
  txt += 'Package gnutls version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}