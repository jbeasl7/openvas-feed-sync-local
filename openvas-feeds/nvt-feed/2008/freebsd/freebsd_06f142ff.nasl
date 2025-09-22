# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.52277");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2004-1487", "CVE-2004-1488");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_name("FreeBSD Ports: wget, wget-devel");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following packages are affected:

  wget, wget-devel, wgetpro, wget+ipv6

CVE-2004-1487
wget 1.8.x and 1.9.x allows a remote malicious web server to overwrite
certain files via a redirection URL containing a '..' that resolves to
the IP address of the malicious server, which bypasses wget's
filtering for '..' sequences.

CVE-2004-1488
wget 1.8.x and 1.9.x does not filter or quote control characters when
displaying HTTP responses to the terminal, which may allow remote
malicious web servers to inject terminal escape sequences and execute
arbitrary code.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://bugs.debian.org/261755");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/11871");
  script_xref(name:"URL", value:"https://marc.info/?l=bugtraq&m=110269474112384");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/06f142ff-4df3-11d9-a9e7-0001020eed82.html");

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

bver = portver(pkg:"wget");
if(!isnull(bver) && revcomp(a:bver, b:"1.10.a1")<0) {
  txt += 'Package wget version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"wget-devel");
if(!isnull(bver) && revcomp(a:bver, b:"1.10.a1")<0) {
  txt += 'Package wget-devel version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"wgetpro");
if(!isnull(bver) && revcomp(a:bver, b:"0")>=0) {
  txt += 'Package wgetpro version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"wget+ipv6");
if(!isnull(bver) && revcomp(a:bver, b:"0")>=0) {
  txt += 'Package wget+ipv6 version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}