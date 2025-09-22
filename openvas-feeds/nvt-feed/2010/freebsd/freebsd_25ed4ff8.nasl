# SPDX-FileCopyrightText: 2010 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.67713");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-07-22 17:43:43 +0200 (Thu, 22 Jul 2010)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2010-2494");
  script_name("FreeBSD Ports: bogofilter");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following packages are affected:

  bogofilter
   bogofilter-sqlite
   bogofilter-tc

CVE-2010-2494
Multiple buffer underflows in the base64 decoder in base64.c in (1)
bogofilter and (2) bogolexer in bogofilter before 1.2.2 allow remote
attackers to cause a denial of service (heap memory corruption and
application crash) via an e-mail message with invalid base64 data that
begins with an = (equals) character.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://bogofilter.sourceforge.net/security/bogofilter-SA-2010-01");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/25ed4ff8-8940-11df-a339-0026189baca3.html");

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

bver = portver(pkg:"bogofilter");
if(!isnull(bver) && revcomp(a:bver, b:"1.2.1_2")<0) {
  txt += 'Package bogofilter version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"bogofilter-sqlite");
if(!isnull(bver) && revcomp(a:bver, b:"1.2.1_1")<0) {
  txt += 'Package bogofilter-sqlite version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"bogofilter-tc");
if(!isnull(bver) && revcomp(a:bver, b:"1.2.1_1")<0) {
  txt += 'Package bogofilter-tc version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}