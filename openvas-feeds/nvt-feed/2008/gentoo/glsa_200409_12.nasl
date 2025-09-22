# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.54669");
  script_version("2023-07-14T16:09:26+0000");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:26 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
  script_cve_id("CVE-2004-0817", "CVE-2004-0802");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Gentoo Security Advisory GLSA 200409-12 (imagemagick imlib)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"ImageMagick, imlib and imlib2 contain exploitable buffer overflow
vulnerabilities in the BMP image processing code.");
  script_tag(name:"solution", value:"All ImageMagick users should upgrade to the latest version:

    # emerge sync

    # emerge -pv '>=media-gfx/imagemagick-6.0.7.1'
    # emerge '>=media-gfx/imagemagick-6.0.7.1'

All imlib users should upgrade to the latest version:

    # emerge sync

    # emerge -pv '>=media-libs/imlib-1.9.14-r2'
    # emerge '>=media-libs/imlib-1.9.14-r2'

All imlib2 users should upgrade to the latest version:

    # emerge sync

    # emerge -pv '>=media-libs/imlib2-1.1.2'
    # emerge '>=media-libs/imlib2-1.1.2'");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200409-12");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=62309");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=62487");
  script_xref(name:"URL", value:"http://studio.imagemagick.org/pipermail/magick-developers/2004-August/002011.html");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2004/Aug/1011104.html");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2004/Aug/1011105.html");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200409-12.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"media-gfx/imagemagick", unaffected: make_list("ge 6.0.7.1"), vulnerable: make_list("lt 6.0.7.1"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"media-libs/imlib", unaffected: make_list("ge 1.9.14-r2"), vulnerable: make_list("lt 1.9.14-r2"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"media-libs/imlib2", unaffected: make_list("ge 1.1.2"), vulnerable: make_list("lt 1.1.2"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
