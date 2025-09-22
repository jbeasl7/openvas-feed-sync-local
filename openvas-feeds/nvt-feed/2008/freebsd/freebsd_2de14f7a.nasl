# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.52420");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2004-0600", "CVE-2004-0686");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("FreeBSD Ports: samba");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following packages are affected:
   samba
   ja-samba

CVE-2004-0600
Buffer overflow in the Samba Web Administration Tool (SWAT) in Samba
3.0.2 to 3.0.4 allows remote attackers to execute arbitrary code via
an invalid base-64 character during HTTP basic authentication.

CVE-2004-0686
Buffer overflow in Samba 2.2.x to 2.2.9, and 3.0.0 to 3.0.4, when the
'mangling method = hash' option is enabled in smb.conf, has unknown
impact and attack vectors.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
software upgrades.");

  script_tag(name:"summary", value:"The remote host is missing an update to the system
as announced in the referenced advisory.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.samba.org/samba/whatsnew/samba-3.0.5.html");
  script_xref(name:"URL", value:"http://www.samba.org/samba/whatsnew/samba-2.2.10.html");
  script_xref(name:"URL", value:"http://secunia.com/advisories/12130");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/369698");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/369706");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/2de14f7a-dad9-11d8-b59a-00061bc2ad93.html");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-bsd.inc");

txt = "";
vuln = FALSE;

bver = portver(pkg:"samba");
if(!isnull(bver) && revcomp(a:bver, b:"3")>=0 && revcomp(a:bver, b:"3.0.5,1")<0) {
  txt += 'Package samba version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"2.2.10")<0) {
  txt += 'Package samba version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"ja-samba");
if(!isnull(bver) && revcomp(a:bver, b:"2.2.10.j1.0")<0) {
  txt += 'Package ja-samba version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}