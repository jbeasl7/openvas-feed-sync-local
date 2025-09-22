# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64433");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-07-29 19:28:37 +0200 (Wed, 29 Jul 2009)");
  script_cve_id("CVE-2009-0386", "CVE-2009-0387", "CVE-2009-0397", "CVE-2009-0586", "CVE-2009-1932");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Gentoo Security Advisory GLSA 200907-11 (gst-plugins-good gst-plugins-base gst-plugins-libpng)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"Multiple vulnerabilities in multiple GStreamer plug-ins might allow for the
execution of arbitrary code.");
  script_tag(name:"solution", value:"All gst-plugins-good users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=media-libs/gst-plugins-good-0.10.14'

All gst-plugins-base users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=media-libs/gst-plugins-base-0.10.22'

All gst-plugins-libpng users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=media-plugins/gst-plugins-libpng-0.10.14-r1'");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200907-11");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=256096");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=261594");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=272972");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200907-11.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"media-libs/gst-plugins-good", unaffected: make_list("ge 0.10.14"), vulnerable: make_list("lt 0.10.14"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"media-libs/gst-plugins-base", unaffected: make_list("ge 0.10.22"), vulnerable: make_list("lt 0.10.22"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"media-plugins/gst-plugins-libpng", unaffected: make_list("ge 0.10.14-r1"), vulnerable: make_list("lt 0.10.14-r1"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
