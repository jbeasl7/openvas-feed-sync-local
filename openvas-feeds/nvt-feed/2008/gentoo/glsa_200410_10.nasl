# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.54701");
  script_cve_id("CVE-2004-0966");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:P/A:N");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
  script_name("Gentoo Security Advisory GLSA 200410-10 (gettext)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"The gettext utility is vulnerable to symlink attacks, potentially allowing
a local user to overwrite or change permissions on arbitrary files with
the rights of the user running gettext, which could be the root user.");
  script_tag(name:"solution", value:"All gettext users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=sys-devel/gettext-0.14.1-r1'");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200410-10");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=66355");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=85766");
  script_xref(name:"URL", value:"http://www.securityfocus.com/advisories/7263");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200410-10.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"sys-devel/gettext", unaffected: make_list("ge 0.14.1-r1", "rge 0.12.1-r2"), vulnerable: make_list("lt 0.14.1-r1"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
