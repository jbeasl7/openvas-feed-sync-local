# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.54957");
  script_cve_id("CVE-2005-1941");
  script_tag(name:"cvss_base", value:"3.7");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:P/I:P/A:P");
  script_version("2024-01-26T14:36:50+0000");
  script_tag(name:"last_modification", value:"2024-01-26 14:36:50 +0000 (Fri, 26 Jan 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-25 21:09:00 +0000 (Thu, 25 Jan 2024)");
  script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
  script_name("Gentoo Security Advisory GLSA 200506-05 (silvercity)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"Executable files with insecure permissions can be modified causing an
unsuspecting user to run arbitrary code.");
  script_tag(name:"solution", value:"All SilverCity users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=app-text/silvercity-0.9.5-r1'");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200506-05");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=93558");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200506-05.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"app-text/silvercity", unaffected: make_list("ge 0.9.5-r1"), vulnerable: make_list("lt 0.9.5-r1"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
