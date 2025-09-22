# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.54873");
  script_version("2023-07-18T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-07-18 05:05:36 +0000 (Tue, 18 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
  script_cve_id("CVE-2005-0605");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Gentoo Security Advisory GLSA 200503-08 (openmotif)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"A new vulnerability has been discovered in libXpm, which is included in
OpenMotif and LessTif, that can potentially lead to remote code execution.");
  script_tag(name:"solution", value:"All OpenMotif users should upgrade to an unaffected version:

    # emerge --sync
    # emerge --ask --oneshot --verbose x11-libs/openmotif

All LessTif users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=x11-libs/lesstif-0.94.0-r2'");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200503-08");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/12714");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=83655");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=83656");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200503-08.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"x11-libs/openmotif", unaffected: make_list("ge 2.2.3-r3", "rge 2.1.30-r9"), vulnerable: make_list("lt 2.2.3-r3"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"x11-libs/lesstif", unaffected: make_list("ge 0.94.0-r2"), vulnerable: make_list("lt 0.94.0-r2"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
