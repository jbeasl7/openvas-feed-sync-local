# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.54822");
  script_version("2023-07-18T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-07-18 05:05:36 +0000 (Tue, 18 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
  script_cve_id("CVE-2005-0116", "CVE-2005-0362", "CVE-2005-0363");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Gentoo Security Advisory GLSA 200501-36 (awstats)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"AWStats fails to validate certain input, which could lead to the remote
execution of arbitrary code or to the leak of information.");
  script_tag(name:"solution", value:"All AWStats users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=net-www/awstats-6.3-r2'

Note: Users with the vhosts USE flag set should manually use webapp-config
to finalize the update.");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200501-36");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=77963");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=81775");
  script_xref(name:"URL", value:"http://awstats.sourceforge.net/docs/awstats_changelog.txt");
  script_xref(name:"URL", value:"http://www.idefense.com/application/poi/display?id=185");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200501-36.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"net-www/awstats", unaffected: make_list("ge 6.3-r2"), vulnerable: make_list("lt 6.3-r2"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
