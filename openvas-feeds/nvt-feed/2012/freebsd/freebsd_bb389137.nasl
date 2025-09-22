# SPDX-FileCopyrightText: 2012 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.70595");
  script_tag(name:"creation_date", value:"2012-02-13 01:48:16 +0100 (Mon, 13 Feb 2012)");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_cve_id("CVE-2011-4597", "CVE-2011-4598");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_version("2023-07-26T05:05:09+0000");
  script_name("FreeBSD Ports: asterisk18");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following packages are affected:

  asterisk18
   asterisk16

CVE-2011-4597
The SIP over UDP implementation in Asterisk Open Source 1.4.x before
1.4.43, 1.6.x before 1.6.2.21, and 1.8.x before 1.8.7.2 uses different
port numbers for responses to invalid requests depending on whether a
SIP username exists, which allows remote attackers to enumerate
usernames via a series of requests.

CVE-2011-4598
channels/chan_sip.c in Asterisk Open Source 1.6.2.x before 1.6.2.21
and 1.8.x before 1.8.7.2, when automon is enabled, allows remote
attackers to cause a denial of service (NULL pointer dereference and
daemon crash) via a crafted sequence of SIP requests.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://downloads.asterisk.org/pub/security/AST-2011-013.html");
  script_xref(name:"URL", value:"http://downloads.asterisk.org/pub/security/AST-2011-014.html");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/bb389137-21fb-11e1-89b4-001ec9578670.html");

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

bver = portver(pkg:"asterisk18");
if(!isnull(bver) && revcomp(a:bver, b:"1.8.7.2")<0) {
  txt += 'Package asterisk18 version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"asterisk16");
if(!isnull(bver) && revcomp(a:bver, b:"1.6.2.21")<0) {
  txt += 'Package asterisk16 version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}