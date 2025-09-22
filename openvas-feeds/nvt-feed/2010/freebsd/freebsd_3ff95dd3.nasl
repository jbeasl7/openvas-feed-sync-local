# SPDX-FileCopyrightText: 2010 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.68103");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-10-10 19:35:00 +0200 (Sun, 10 Oct 2010)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2010-3082");
  script_name("django -- cross-site scripting vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following packages are affected:

  py23-django
   py24-django
   py25-django
   py26-django
   py30-django
   py31-django
   py23-django-devel
   py24-django-devel
   py25-django-devel
   py26-django-devel
   py30-django-devel
   py31-django-devel

CVE-2010-3082
Cross-site scripting (XSS) vulnerability in Django 1.2.x before 1.2.2
allows remote attackers to inject arbitrary web script or HTML via a
csrfmiddlewaretoken (aka csrf_token) cookie.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/61729");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/43116");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/3ff95dd3-c291-11df-b0dc-00215c6a37bb.html");

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
if(!isnull(bver) && revcomp(a:bver, b:"1.2")>0 && revcomp(a:bver, b:"1.2.2")<0) {
  txt += 'Package py23-django version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"py24-django");
if(!isnull(bver) && revcomp(a:bver, b:"1.2")>0 && revcomp(a:bver, b:"1.2.2")<0) {
  txt += 'Package py24-django version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"py25-django");
if(!isnull(bver) && revcomp(a:bver, b:"1.2")>0 && revcomp(a:bver, b:"1.2.2")<0) {
  txt += 'Package py25-django version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"py26-django");
if(!isnull(bver) && revcomp(a:bver, b:"1.2")>0 && revcomp(a:bver, b:"1.2.2")<0) {
  txt += 'Package py26-django version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"py30-django");
if(!isnull(bver) && revcomp(a:bver, b:"1.2")>0 && revcomp(a:bver, b:"1.2.2")<0) {
  txt += 'Package py30-django version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"py31-django");
if(!isnull(bver) && revcomp(a:bver, b:"1.2")>0 && revcomp(a:bver, b:"1.2.2")<0) {
  txt += 'Package py31-django version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"py23-django-devel");
if(!isnull(bver) && revcomp(a:bver, b:"13698,1")<0) {
  txt += 'Package py23-django-devel version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"py24-django-devel");
if(!isnull(bver) && revcomp(a:bver, b:"13698,1")<0) {
  txt += 'Package py24-django-devel version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"py25-django-devel");
if(!isnull(bver) && revcomp(a:bver, b:"13698,1")<0) {
  txt += 'Package py25-django-devel version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"py26-django-devel");
if(!isnull(bver) && revcomp(a:bver, b:"13698,1")<0) {
  txt += 'Package py26-django-devel version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"py30-django-devel");
if(!isnull(bver) && revcomp(a:bver, b:"13698,1")<0) {
  txt += 'Package py30-django-devel version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"py31-django-devel");
if(!isnull(bver) && revcomp(a:bver, b:"13698,1")<0) {
  txt += 'Package py31-django-devel version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}