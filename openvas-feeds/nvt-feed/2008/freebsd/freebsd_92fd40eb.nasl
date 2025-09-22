# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.56522");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2006-1059");
  script_tag(name:"cvss_base", value:"1.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:P/I:N/A:N");
  script_name("FreeBSD Ports: samba");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following packages are affected:

  samba
   ja-samba

CVE-2006-1059
The winbindd daemon in Samba 3.0.21 to 3.0.21c writes the machine
trust account password in cleartext in log files, which allows local
users to obtain the password and spoof the server in the domain.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://us1.samba.org/samba/security/CAN-2006-1059.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/17314");
  script_xref(name:"URL", value:"http://secunia.com/advisories/19455/");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/92fd40eb-c458-11da-9c79-00123ffe8333.html");

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

bver = portver(pkg:"samba");
if(!isnull(bver) && revcomp(a:bver, b:"3.0.21a,1")>=0 && revcomp(a:bver, b:"3.0.22,1")<0) {
  txt += 'Package samba version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"ja-samba");
if(!isnull(bver) && revcomp(a:bver, b:"3.0.21a,1")>=0 && revcomp(a:bver, b:"3.0.22,1")<0) {
  txt += 'Package ja-samba version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}