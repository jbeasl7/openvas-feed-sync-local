# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.57460");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2006-4600");
  script_tag(name:"cvss_base", value:"2.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:S/C:N/I:P/A:N");
  script_name("FreeBSD Ports: openldap-server, openldap-sasl-server");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following packages are affected:

  openldap-server openldap-sasl-server");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://www.openldap.org/its/index.cgi/Software%20Bugs?id=4587");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/19832");
  script_xref(name:"URL", value:"http://www.openldap.org/lists/openldap-announce/200608/msg00000.html");
  script_xref(name:"URL", value:"http://secunia.com/advisories/21721");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2006/Sep/1016783.html");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/ae7124ff-547c-11db-8f1a-000a48049292.html");

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

bver = portver(pkg:"openldap-server");
if(!isnull(bver) && revcomp(a:bver, b:"2.3.25")<0) {
  txt += 'Package openldap-server version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"openldap-sasl-server");
if(!isnull(bver) && revcomp(a:bver, b:"2.3.25")<0) {
  txt += 'Package openldap-sasl-server version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}