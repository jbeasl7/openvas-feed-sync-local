# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63157");
  script_version("2023-07-14T16:09:26+0000");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:26 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-01-13 22:38:32 +0100 (Tue, 13 Jan 2009)");
  script_cve_id("CVE-2006-2236");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_name("Gentoo Security Advisory GLSA 200901-06 (tremulous tremulous-bin)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"A buffer overflow vulnerability has been discovered in Tremulous.");
  script_tag(name:"solution", value:"Tremulous users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=games-fps/tremulous-1.1.0-r2'

Note: The binary version of Tremulous has been removed from the Portage
tree.");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200901-06");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=222119");
  script_xref(name:"URL", value:"http://www.gentoo.org/security/en/glsa/glsa-200605-12.xml");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200901-06.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"games-fps/tremulous", unaffected: make_list("ge 1.1.0-r2"), vulnerable: make_list("lt 1.1.0-r2"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"games-fps/tremulous-bin", unaffected: make_list(), vulnerable: make_list("lt 1.1.0"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
