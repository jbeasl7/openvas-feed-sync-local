# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.61915");
  script_version("2023-07-26T05:05:08+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:08 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-11-24 23:46:43 +0100 (Mon, 24 Nov 2008)");
  script_cve_id("CVE-2008-3102");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("FreeBSD Ports: mantis");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following package is affected: mantis

CVE-2008-3102
Mantis 1.1.x through 1.1.2 and 1.2.x through 1.2.0a2 does not set the
secure flag for the session cookie in an https session, which can
cause the cookie to be sent in http requests and make it easier for
remote attackers to capture this cookie.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://www.mantisbt.org/bugs/view.php?id=9524");
  script_xref(name:"URL", value:"http://www.mantisbt.org/bugs/view.php?id=9533");
  script_xref(name:"URL", value:"http://enablesecurity.com/2008/08/11/surf-jack-https-will-not-save-you/");
  script_xref(name:"URL", value:"http://int21.de/cve/CVE-2008-3102-mantis.html");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/00d6040a-b8e0-11dd-a578-0030843d3802.html");

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

bver = portver(pkg:"mantis");
if(!isnull(bver) && revcomp(a:bver, b:"1.1.3")<0) {
  txt += 'Package mantis version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}