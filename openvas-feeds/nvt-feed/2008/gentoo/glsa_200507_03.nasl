# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.54979");
  script_version("2023-07-19T05:05:15+0000");
  script_cve_id("CVE-2005-2086");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Gentoo Security Advisory GLSA 200507-03 (phpBB)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"A vulnerability in phpBB allows a remote attacker to execute arbitrary
commands with the rights of the web server.");
  script_tag(name:"solution", value:"The phpBB package is no longer supported by Gentoo Linux and has been
removed from the Portage repository, no further announcements will be
issued regarding phpBB updates. Users who wish to continue using phpBB are
advised to monitor and refer to the vendor homepage linked in the references for more information.

To continue using the Gentoo-provided phpBB package, please refer to the
Portage documentation on unmasking packages and upgrade to 2.0.16.");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200507-03");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=97278");
  script_xref(name:"URL", value:"http://www.phpbb.com/phpBB/viewtopic.php?f=14&t=302011");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200507-03.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"www-apps/phpBB", unaffected: make_list("ge 2.0.16"), vulnerable: make_list("lt 2.0.16"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
