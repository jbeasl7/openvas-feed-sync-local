# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.55024");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2005-2430", "CVE-2005-2431");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("FreeBSD Ports: gforge");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following package is affected: gforge

CVE-2005-2430
Multiple cross-site scripting (XSS) vulnerabilities in GForge 4.5
allow remote attackers to inject arbitrary web script or HTML via the
(1) forum_id or (2) group_id parameter to forum.php, (3)
project_task_id parameter to task.php, (4) id parameter to detail.php,
(5) the text field on the search page, (6) group_id parameter to
qrs.php, (7) form, (8) rows, (9) cols or (10) wrap parameter to
notepad.php, or the login field on the login form.

CVE-2005-2431
The (1) lost password and (2) account pending features in GForge 4.5
do not properly set a limit on the number of e-mails sent to an e-mail
address, which allows remote attackers to send a large number of
messages to arbitrary e-mail addresses (aka mail bomb).");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"https://marc.info/?l=bugtraq&m=112259845904350");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/14405");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/d7cd5015-08c9-11da-bc08-0001020eed82.html");

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

bver = portver(pkg:"gforge");
if(!isnull(bver) && revcomp(a:bver, b:"0")>0) {
  txt += 'Package gforge version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}