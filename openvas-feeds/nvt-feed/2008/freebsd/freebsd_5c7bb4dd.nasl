# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.52223");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2005-0129", "CVE-2005-0130", "CVE-2005-0131");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("FreeBSD Ports: konversation");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following package is affected: konversation

CVE-2005-0129
The Quick Buttons feature in Konversation 0.15 allows remote attackers
to execute certain IRC commands via a channel name containing '%'
variables, which are recursively expanded by the
Server::parseWildcards function when the Part Button is selected.

CVE-2005-0130
Certain Perl scripts in Konversation 0.15 allow remote attackers to
execute arbitrary commands via shell metacharacters in (1) channel
names or (2) song names that are not properly quoted when the user
runs IRC scripts.

CVE-2005-0131
The Quick Connection dialog in Konversation 0.15 inadvertently uses
the user-provided password as the nickname instead of the
user-provided nickname when connecting to the IRC server, which could
leak the password to other users.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"https://marc.info/?l=full-disclosure&m=110616016509114");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/5c7bb4dd-6a56-11d9-97ec-000c6e8f12ef.html");

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

bver = portver(pkg:"konversation");
if(!isnull(bver) && revcomp(a:bver, b:"0.15")<0) {
  txt += 'Package konversation version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}
