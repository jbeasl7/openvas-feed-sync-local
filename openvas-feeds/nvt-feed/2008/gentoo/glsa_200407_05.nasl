# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.54612");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
  script_cve_id("CVE-2004-0419");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Gentoo Security Advisory GLSA 200407-05 (xdm)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"XDM will open TCP sockets for its chooser, even if the
DisplayManager.requestPort setting is set to 0. This may allow authorized
users to access a machine remotely via X, even if the administrator has
configured XDM to refuse such connections.");
  script_tag(name:"solution", value:"If you are using XFree86, you should run the following:

    # emerge sync

    # emerge -pv '>=x11-base/xfree-4.3.0-r6'
    # emerge '>=x11-base/xfree-4.3.0-r6'

If you are using X.org's X11 server, you should run the following:

    # emerge sync

    # emerge -pv '>=x11-base/xorg-x11-6.7.0-r1'
    # emerge '>=x11-base/xorg-x11-6.7.0-r1'");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200407-05");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/10423");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=53226");
  script_xref(name:"URL", value:"http://bugs.xfree86.org/show_bug.cgi?id=1376");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200407-05.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"x11-base/xfree", unaffected: make_list("ge 4.3.0-r6"), vulnerable: make_list("le 4.3.0-r5"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"x11-base/xorg-x11", unaffected: make_list("ge 6.7.0-r1"), vulnerable: make_list("le 6.7.0"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
