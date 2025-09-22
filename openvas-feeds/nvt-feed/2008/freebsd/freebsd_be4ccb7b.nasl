# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.56521");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2006-1629");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_name("FreeBSD Ports: openvpn");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following package is affected: openvpn

CVE-2006-1629
OpenVPN 2.0 through 2.0.5 allows remote malicious servers to execute
arbitrary code on the client by using setenv with the LD_PRELOAD
environment variable.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://www.osreviews.net/reviews/security/openvpn-print");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/17392");
  script_xref(name:"URL", value:"http://openvpn.net/changelog.html");
  script_xref(name:"URL", value:"http://sourceforge.net/mailarchive/message.php?msg_id=15298074");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/be4ccb7b-c48b-11da-ae12-0002b3b60e4c.html");

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

bver = portver(pkg:"openvpn");
if(!isnull(bver) && revcomp(a:bver, b:"2.0")>=0 && revcomp(a:bver, b:"2.0.6")<0) {
  txt += 'Package openvpn version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}