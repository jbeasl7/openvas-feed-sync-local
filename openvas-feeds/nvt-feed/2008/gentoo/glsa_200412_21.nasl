# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.54780");
  script_version("2023-07-14T16:09:26+0000");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:26 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_name("Gentoo Security Advisory GLSA 200412-21 (MPlayer)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"Multiple overflow vulnerabilities have been found in MPlayer, potentially
resulting in remote executing of arbitrary code.");
  script_tag(name:"solution", value:"All MPlayer users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=media-video/mplayer-1.0_pre5-r5'");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200412-21");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=74473");
  script_xref(name:"URL", value:"http://www.idefense.com/application/poi/display?id=168&type=vulnerabilities");
  script_xref(name:"URL", value:"http://www.idefense.com/application/poi/display?id=167&type=vulnerabilities");
  script_xref(name:"URL", value:"http://www.idefense.com/application/poi/display?id=166&type=vulnerabilities");
  script_xref(name:"URL", value:"http://tigger.uic.edu/~jlongs2/holes/mplayer.txt");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200412-21.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"media-video/mplayer", unaffected: make_list("ge 1.0_pre5-r5"), vulnerable: make_list("le 1.0_pre5-r4"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
