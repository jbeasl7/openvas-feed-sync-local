# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.55856");
  script_cve_id("CVE-2005-3580", "CVE-2005-3581", "CVE-2005-3582");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_version("2023-07-14T16:09:26+0000");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:26 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
  script_name("Gentoo Security Advisory GLSA 200511-02 (QDBM ImageMagick GDAL)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"Multiple packages suffer from RUNPATH issues that may allow users in the
'portage' group to escalate privileges.");
  script_tag(name:"solution", value:"All QDBM users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=dev-db/qdbm-1.8.33-r2'

All ImageMagick users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose
'>=media-gfx/imagemagick-6.2.4.2-r1'

All GDAL users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose sci-libs/gdal");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200511-02");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=105717");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=105760");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=108534");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200511-02.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"dev-db/qdbm", unaffected: make_list("ge 1.8.33-r2"), vulnerable: make_list("lt 1.8.33-r2"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"media-gfx/imagemagick", unaffected: make_list("ge 6.2.4.2-r1"), vulnerable: make_list("lt 6.2.4.2-r1"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"sci-libs/gdal", unaffected: make_list("ge 1.3.0-r1", "rge 1.2.6-r4"), vulnerable: make_list("lt 1.3.0-r1"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
