# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.52197");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2005-0089");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("FreeBSD Ports: python, python23, python22, python-devel");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following packages are affected:

  python
   python23
   python22
   python-devel

CVE-2005-0089
The SimpleXMLRPCServer library module in Python 2.2, 2.3 before 2.3.5,
and 2.4, when used by XML-RPC servers that use the register_instance
method to register an object without a _dispatch method, allows remote
attackers to read or modify globals of the associated module, and
possibly execute arbitrary code, via dotted attributes.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://www.python.org/security/PSF-2005-001/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/12437");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/6afa87d3-764b-11d9-b0e7-0000e249a0a2.html");

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

bver = portver(pkg:"python");
if(!isnull(bver) && revcomp(a:bver, b:"2.2")>=0 && revcomp(a:bver, b:"2.2.3_7")<0) {
  txt += 'Package python version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"2.3")>=0 && revcomp(a:bver, b:"2.3.4_4")<0) {
  txt += 'Package python version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"2.4")>=0 && revcomp(a:bver, b:"2.4_1")<0) {
  txt += 'Package python version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"2.5.a0.20050129")>=0 && revcomp(a:bver, b:"2.5.a0.20050129_1")<0) {
  txt += 'Package python version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"python23");
if(!isnull(bver) && revcomp(a:bver, b:"2.2")>=0 && revcomp(a:bver, b:"2.2.3_7")<0) {
  txt += 'Package python23 version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"2.3")>=0 && revcomp(a:bver, b:"2.3.4_4")<0) {
  txt += 'Package python23 version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"2.4")>=0 && revcomp(a:bver, b:"2.4_1")<0) {
  txt += 'Package python23 version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"2.5.a0.20050129")>=0 && revcomp(a:bver, b:"2.5.a0.20050129_1")<0) {
  txt += 'Package python23 version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"python22");
if(!isnull(bver) && revcomp(a:bver, b:"2.2")>=0 && revcomp(a:bver, b:"2.2.3_7")<0) {
  txt += 'Package python22 version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"2.3")>=0 && revcomp(a:bver, b:"2.3.4_4")<0) {
  txt += 'Package python22 version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"2.4")>=0 && revcomp(a:bver, b:"2.4_1")<0) {
  txt += 'Package python22 version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"2.5.a0.20050129")>=0 && revcomp(a:bver, b:"2.5.a0.20050129_1")<0) {
  txt += 'Package python22 version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"python-devel");
if(!isnull(bver) && revcomp(a:bver, b:"2.2")>=0 && revcomp(a:bver, b:"2.2.3_7")<0) {
  txt += 'Package python-devel version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"2.3")>=0 && revcomp(a:bver, b:"2.3.4_4")<0) {
  txt += 'Package python-devel version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"2.4")>=0 && revcomp(a:bver, b:"2.4_1")<0) {
  txt += 'Package python-devel version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"2.5.a0.20050129")>=0 && revcomp(a:bver, b:"2.5.a0.20050129_1")<0) {
  txt += 'Package python-devel version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}