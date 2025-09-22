# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.56450");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2005-0469", "CVE-2005-2040", "CVE-2006-0582", "CVE-2006-0677");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_name("FreeBSD Ports: heimdal");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following package is affected: heimdal

CVE-2005-0469
Buffer overflow in the slc_add_reply function in various BSD-based
Telnet clients, when handling LINEMODE suboptions, allows remote
attackers to execute arbitrary code via a reply with a large number of
Set Local Character (SLC) commands.

CVE-2005-2040
Multiple buffer overflows in the getterminaltype function in telnetd
for Heimdal before 0.6.5 may allow remote attackers to execute
arbitrary code, a different vulnerability than CVE-2005-0468 and
CVE-2005-0469.

CVE-2006-0582
Unspecified vulnerability in rshd in Heimdal 0.6.x before 0.6.6 and
0.7.x before 0.7.2, when storing forwarded credentials, allows
attackers to overwrite arbitrary files and change file ownership via
unknown vectors.

CVE-2006-0677
telnetd in Heimdal 0.6.x before 0.6.6 and 0.7.x before 0.7.2 allows
remote unauthenticated attackers to cause a denial of service (server
crash) via unknown vectors that trigger a null dereference.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://www.pdc.kth.se/heimdal/advisory/2005-04-20");
  script_xref(name:"URL", value:"http://www.pdc.kth.se/heimdal/advisory/2005-06-20");
  script_xref(name:"URL", value:"http://www.pdc.kth.se/heimdal/advisory/2006-02-06");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/b62c80c2-b81a-11da-bec5-00123ffe8333.html");

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

bver = portver(pkg:"heimdal");
if(!isnull(bver) && revcomp(a:bver, b:"0.6.6")<0) {
  txt += 'Package heimdal version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}