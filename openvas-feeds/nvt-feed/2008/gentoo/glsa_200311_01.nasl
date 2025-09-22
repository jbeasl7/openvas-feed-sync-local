# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.54500");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
  script_cve_id("CVE-2003-0690", "CVE-2003-0692");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Gentoo Security Advisory GLSA 200311-01 (kdebase)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"A bug in KDM can allow privilege escalation with certain configurations of
PAM modules.");
  script_tag(name:"solution", value:"It is recommended that all Gentoo Linux users who are running
kde-base/kdebase < =3.1.3 upgrade:

    # emerge sync
    # emerge -pv '>=kde-base/kde-3.1.4'
    # emerge '>=kde-base/kde-3.1.4'
    # emerge clean");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200311-01");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=29406");
  script_xref(name:"URL", value:"http://www.kde.org/info/security/advisory-20030916-1.txt");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200311-01.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"kde-base/kdebase", unaffected: make_list("ge 3.1.4"), vulnerable: make_list("le 3.1.3"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
