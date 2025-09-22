# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.54775");
  script_version("2023-07-14T16:09:26+0000");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:26 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
  script_cve_id("CVE-2004-1171", "CVE-2004-1158");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Gentoo Security Advisory GLSA 200412-16 (KDE)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"kdelibs and kdebase contain a flaw allowing password disclosure when
creating a link to a remote file. Furthermore Konqueror is vulnerable to
window injection.");
  script_tag(name:"solution", value:"All kdelibs users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=kde-base/kdelibs-3.2.3-r4'

All kdebase users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=kde-base/kdebase-3.2.3-r3'");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200412-16");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=72804");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=73869");
  script_xref(name:"URL", value:"http://www.kde.org/info/security/advisory-20041209-1.txt");
  script_xref(name:"URL", value:"http://www.kde.org/info/security/advisory-20041213-1.txt");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200412-16.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"kde-base/kdelibs", unaffected: make_list("rge 3.2.3-r4", "rge 3.3.1-r2", "ge 3.3.2-r1"), vulnerable: make_list("lt 3.3.2-r1"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"kde-base/kdebase", unaffected: make_list("rge 3.2.3-r3", "rge 3.3.1-r2"), vulnerable: make_list("lt 3.3.2-r1"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
