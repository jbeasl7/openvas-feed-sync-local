# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.54734");
  script_cve_id("CVE-2004-1107", "CVE-2004-1108");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:P/A:N");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
  script_name("Gentoo Security Advisory GLSA 200411-13 (portage gentoolkit)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"dispatch-conf (included in Portage) and qpkg (included in Gentoolkit) are
vulnerable to symlink attacks, potentially allowing a local user to
overwrite arbitrary files with the rights of the user running the script.");
  script_tag(name:"solution", value:"All Portage users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=sys-apps/portage-2.0.51-r3'

All Gentoolkit users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose
'>=app-portage/gentoolkit-0.2.0_pre8-r1'");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200411-13");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=68846");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=69147");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200411-13.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"sys-apps/portage", unaffected: make_list("ge 2.0.51-r3"), vulnerable: make_list("le 2.0.51-r2"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"app-portage/gentoolkit", unaffected: make_list("ge 0.2.0_pre10-r1", "rge 0.2.0_pre8-r1"), vulnerable: make_list("le 0.2.0_pre10"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
