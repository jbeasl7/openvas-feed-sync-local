# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.55177");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2005-2549", "CVE-2005-2550");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("FreeBSD Ports: evolution");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following package is affected: evolution

CVE-2005-2549
Multiple format string vulnerabilities in Evolution 1.5 through
2.3.6.1 allow remote attackers to cause a denial of service (crash)
and possibly execute arbitrary code via (1) full vCard data, (2)
contact data from remote LDAP servers, or (3) task list data from
remote servers.

CVE-2005-2550
Format string vulnerability in Evolution 1.4 through 2.3.6.1 allows
remote attackers to cause a denial of service (crash) and possibly
execute arbitrary code via the calendar entries such as task lists,
which are not properly handled when the user selects the Calendars
tab.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://www.sitic.se/eng/advisories_and_recommendations/sa05-001.html");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/e5afdf63-1746-11da-978e-0001020eed82.html");

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

bver = portver(pkg:"evolution");
if(!isnull(bver) && revcomp(a:bver, b:"1.5")>0 && revcomp(a:bver, b:"2.3.7")<0) {
  txt += 'Package evolution version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}