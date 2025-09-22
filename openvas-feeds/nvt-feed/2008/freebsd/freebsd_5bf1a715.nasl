# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53003");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2005-0446", "CVE-2005-0096", "CVE-2005-0097");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("FreeBSD Ports: squid");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following package is affected: squid

CVE-2005-0446
Squid 2.5.STABLE8 and earlier allows remote attackers to cause a
denial of service (crash) via certain DNS responses regarding (1)
Fully Qualified Domain Names (FQDN) in fqdncache.c or (2) IP addresses
in ipcache.c, which trigger an assertion failure.

CVE-2005-0096
Memory leak in the NTLM fakeauth_auth helper for Squid 2.5.STABLE7 and
earlier allows remote attackers to cause a denial of service (memory
consumption).

CVE-2005-0097
The NTLM component in Squid 2.5.STABLE7 and earlier allows remote
attackers to cause a denial of service (crash) via a malformed NTLM
type 3 message that triggers a NULL dereference.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://www.squid-cache.org/Versions/v2/2.5/bugs/#squid-2.5.STABLE8-dns_assert");
  script_xref(name:"URL", value:"http://www.squid-cache.org/Versions/v2/2.5/bugs/#squid-2.5.STABLE7-fakeauth_auth");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/5bf1a715-cc57-440f-b0a5-6406961c54a7.html");

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

bver = portver(pkg:"squid");
if(!isnull(bver) && revcomp(a:bver, b:"2.5.9")<0) {
  txt += 'Package squid version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}