# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.62858");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-12-10 05:23:56 +0100 (Wed, 10 Dec 2008)");
  script_cve_id("CVE-2008-2276", "CVE-2008-3331", "CVE-2008-3332", "CVE-2008-3333");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("FreeBSD Ports: mantis");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following package is affected: mantis

CVE-2008-2276
Cross-site request forgery (CSRF) vulnerability in
manage_user_create.php in Mantis 1.1.1 allows remote attackers to
create new administrative users via a crafted link.
CVE-2008-3331
Cross-site scripting (XSS) vulnerability in return_dynamic_filters.php
in Mantis before 1.1.2 allows remote attackers to inject arbitrary web
script or HTML via the filter_target parameter.
CVE-2008-3332
Eval injection vulnerability in adm_config_set.php in Mantis before
1.1.2 allows remote authenticated administrators to execute arbitrary
code via the value parameter.
CVE-2008-3333
Directory traversal vulnerability in core/lang_api.php in Mantis
before 1.1.2 allows remote attackers to include and execute arbitrary
files via the language parameter to the user preferences page
(account_prefs_update.php).");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/30270/");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/29255141-c3df-11dd-a721-0030843d3802.html");

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
if(!isnull(bver) && revcomp(a:bver, b:"1.1.2")<0) {
  txt += 'Package mantis version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}