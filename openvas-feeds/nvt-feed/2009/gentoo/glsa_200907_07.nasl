# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64429");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-07-29 19:28:37 +0200 (Wed, 29 Jul 2009)");
  script_cve_id("CVE-2009-1438", "CVE-2009-1513");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Gentoo Security Advisory GLSA 200907-07 (libmodplug gst-plugins-bad)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"ModPlug contains several buffer overflows that could lead to the execution
of arbitrary code.");
  script_tag(name:"solution", value:"All ModPlug users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=media-libs/libmodplug-0.8.7'

gst-plugins-bad 0.10.11 and later versions do not include the ModPlug
    plug-in (it has been moved to media-plugins/gst-plugins-modplug). All
    gst-plugins-bad users should upgrade to the latest version and install
    media-plugins/gst-plugins-modplug:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=media-libs/gst-plugins-bad-0.10.11'
    # emerge --ask --verbose 'media-plugins/gst-plugins-modplug'");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200907-07");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=266913");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200907-07.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"media-libs/libmodplug", unaffected: make_list("ge 0.8.7"), vulnerable: make_list("lt 0.8.7"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"media-libs/gst-plugins-bad", unaffected: make_list("ge 0.10.11"), vulnerable: make_list("lt 0.10.11"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
