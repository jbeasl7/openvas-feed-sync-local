# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63035");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-12-23 18:28:16 +0100 (Tue, 23 Dec 2008)");
  script_cve_id("CVE-2006-1495", "CVE-2008-4303", "CVE-2008-4304", "CVE-2008-4305");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Gentoo Security Advisory GLSA 200812-20 (phpcollab)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"Multiple vulnerabilities have been discovered in phpCollab allowing for
remote injection of shell commands, PHP code and SQL statements.");
  script_tag(name:"solution", value:"phpCollab has been removed from the Portage tree. We recommend that users
unmerge phpCollab:

    # emerge --unmerge 'www-apps/phpcollab'");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200812-20");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=235052");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200812-20.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"www-apps/phpcollab", unaffected: make_list(), vulnerable: make_list("le 2.5_rc3"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
