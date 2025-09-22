# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.61058");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2008-2302");
  script_name("FreeBSD Ports: py23-django, py24-django, py25-django");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following packages are affected:

  py23-django
   py24-django
   py25-django
   py23-django-devel
   py24-django-devel
   py25-django-devel");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://www.djangoproject.com/weblog/2008/may/14/security/");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/f49ba347-2190-11dd-907c-001c2514716c.html");

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

bver = portver(pkg:"py23-django");
if(!isnull(bver) && revcomp(a:bver, b:"0.96.2")<0) {
  txt += 'Package py23-django version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"py24-django");
if(!isnull(bver) && revcomp(a:bver, b:"0.96.2")<0) {
  txt += 'Package py24-django version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"py25-django");
if(!isnull(bver) && revcomp(a:bver, b:"0.96.2")<0) {
  txt += 'Package py25-django version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"py23-django-devel");
if(!isnull(bver) && revcomp(a:bver, b:"20080511")<0) {
  txt += 'Package py23-django-devel version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"py24-django-devel");
if(!isnull(bver) && revcomp(a:bver, b:"20080511")<0) {
  txt += 'Package py24-django-devel version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"py25-django-devel");
if(!isnull(bver) && revcomp(a:bver, b:"20080511")<0) {
  txt += 'Package py25-django-devel version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}