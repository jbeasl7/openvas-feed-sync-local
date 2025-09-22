# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.66109");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-10-27 01:37:56 +0100 (Tue, 27 Oct 2009)");
  script_cve_id("CVE-2009-1376", "CVE-2009-1889", "CVE-2009-2694", "CVE-2009-3026");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Gentoo Security Advisory GLSA 200910-02 (pidgin)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"Multiple vulnerabilities have been discovered in Pidgin, leading to the
    remote execution of arbitrary code, unauthorized information
disclosure, or
    Denial of Service.");
  script_tag(name:"solution", value:"All Pidgin users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose =net-im/pidgin-2.5.9-r1");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200910-02");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=276000");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=281545");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=283324");
  script_xref(name:"URL", value:"http://www.gentoo.org/security/en/glsa/glsa-200905-07.xml");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200910-02.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"net-im/pidgin", unaffected: make_list("ge 2.5.9-r1"), vulnerable: make_list("lt 2.5.9-r1"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
