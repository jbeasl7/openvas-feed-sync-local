# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63688");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-03-31 19:20:21 +0200 (Tue, 31 Mar 2009)");
  script_cve_id("CVE-2008-3162", "CVE-2008-4866", "CVE-2008-4867", "CVE-2008-4868", "CVE-2008-4869", "CVE-2009-0385");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Gentoo Security Advisory GLSA 200903-33 (ffmpeg gst-plugins-ffmpeg mplayer)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"Multiple vulnerabilities in FFmpeg may lead to the remote execution of
arbitrary code or a Denial of Service.");
  script_tag(name:"solution", value:"All FFmpeg users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=media-video/ffmpeg-0.4.9_p20090201'

All gst-plugins-ffmpeg users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=media-plugins/gst-plugins-ffmpeg-0.10.5'

All Mplayer users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=media-video/mplayer-1.0_rc2_p28450'");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200903-33");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=231831");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=231834");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=245313");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=257217");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=257381");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200903-33.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"media-video/ffmpeg", unaffected: make_list("ge 0.4.9_p20090201"), vulnerable: make_list("lt 0.4.9_p20090201"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"media-plugins/gst-plugins-ffmpeg", unaffected: make_list("ge 0.10.5"), vulnerable: make_list("lt 0.10.5"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"media-video/mplayer", unaffected: make_list("ge 1.0_rc2_p28450"), vulnerable: make_list("lt 1.0_rc2_p28450"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
