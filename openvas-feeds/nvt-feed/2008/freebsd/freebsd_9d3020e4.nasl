# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.61798");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-11-01 01:55:10 +0100 (Sat, 01 Nov 2008)");
  script_cve_id("CVE-2007-6461", "CVE-2008-1165", "CVE-2008-1166");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("FreeBSD Ports: flyspray");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following package is affected: flyspray

CVE-2007-6461
Multiple cross-site scripting (XSS) vulnerabilities in index.php in
Flyspray 0.9.9 through 0.9.9.3 allow remote attackers to inject
arbitrary web script or HTML via (1) the query string in an index
action, related to the savesearch JavaScript function, and (2) the
details parameter in a details action, related to the History tab and
the getHistory JavaScript function.

CVE-2008-1165
Multiple cross-site scripting (XSS) vulnerabilities in Flyspray 0.9.9
through 0.9.9.4 allow remote attackers to inject arbitrary web script
or HTML via (1) a forced SQL error message or (2) old_value and
new_value database fields in task summaries, related to the
item_summary parameter in a details action in index.php.  NOTE: some of
these details are obtained from third party information.

CVE-2008-1166
Flyspray 0.9.9.4 generates different error messages depending on
whether the username is valid or invalid, which allows remote
attackers to enumerate usernames.  NOTE: the provenance of this
information is unknown. The details are obtained solely from third
party information.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/29215");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/9d3020e4-a2c4-11dd-a9f9-0030843d3802.html");

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

bver = portver(pkg:"flyspray");
if(!isnull(bver) && revcomp(a:bver, b:"0.9.9.5.1")<0) {
  txt += 'Package flyspray version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}