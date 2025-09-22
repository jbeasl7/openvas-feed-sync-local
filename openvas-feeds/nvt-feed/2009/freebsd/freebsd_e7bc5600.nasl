# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.66611");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-12-30 21:58:43 +0100 (Wed, 30 Dec 2009)");
  script_cve_id("CVE-2009-4034", "CVE-2009-4136");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_name("FreeBSD Ports: postgresql-client, postgresql-server");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following packages are affected:

  postgresql-client
   postgresql-server

CVE-2009-4034
PostgreSQL 7.4.x before 7.4.27, 8.0.x before 8.0.23, 8.1.x before
8.1.19, 8.2.x before 8.2.15, 8.3.x before 8.3.9, and 8.4.x before
8.4.2 does not properly handle a '\0' character in a domain name in
the subject's Common Name (CN) field of an X.509 certificate, which
(1) allows man-in-the-middle attackers to spoof arbitrary SSL-based
PostgreSQL servers via a crafted server certificate issued by a
legitimate Certification Authority, and (2) allows remote attackers to
bypass intended client-hostname restrictions via a crafted client
certificate issued by a legitimate Certification Authority, a related
issue to CVE-2009-2408.

CVE-2009-4136
PostgreSQL 7.4.x before 7.4.27, 8.0.x before 8.0.23, 8.1.x before
8.1.19, 8.2.x before 8.2.15, 8.3.x before 8.3.9, and 8.4.x before
8.4.2 does not properly manage session-local state during execution of
an index function by a database superuser, which allows remote
authenticated users to gain privileges via a table with crafted index
functions, as demonstrated by functions that modify (1) search_path or
(2) a prepared statement, a related issue to CVE-2007-6600 and
CVE-2009-3230.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

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

bver = portver(pkg:"postgresql-client");
if(!isnull(bver) && revcomp(a:bver, b:"7.4")>=0 && revcomp(a:bver, b:"7.4.27")<0) {
  txt += 'Package postgresql-client version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"8.0")>=0 && revcomp(a:bver, b:"8.0.23")<0) {
  txt += 'Package postgresql-client version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"8.1")>=0 && revcomp(a:bver, b:"8.1.19")<0) {
  txt += 'Package postgresql-client version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"8.2")>=0 && revcomp(a:bver, b:"8.2.15")<0) {
  txt += 'Package postgresql-client version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"8.3")>=0 && revcomp(a:bver, b:"8.3.9")<0) {
  txt += 'Package postgresql-client version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"8.4")>=0 && revcomp(a:bver, b:"8.4.2")<0) {
  txt += 'Package postgresql-client version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"postgresql-server");
if(!isnull(bver) && revcomp(a:bver, b:"7.4")>=0 && revcomp(a:bver, b:"7.4.27")<0) {
  txt += 'Package postgresql-server version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"8.0")>=0 && revcomp(a:bver, b:"8.0.23")<0) {
  txt += 'Package postgresql-server version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"8.1")>=0 && revcomp(a:bver, b:"8.1.19")<0) {
  txt += 'Package postgresql-server version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"8.2")>=0 && revcomp(a:bver, b:"8.2.15")<0) {
  txt += 'Package postgresql-server version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"8.3")>=0 && revcomp(a:bver, b:"8.3.9")<0) {
  txt += 'Package postgresql-server version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"8.4")>=0 && revcomp(a:bver, b:"8.4.2")<0) {
  txt += 'Package postgresql-server version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}