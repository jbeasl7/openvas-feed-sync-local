# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63940");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-05-05 16:00:35 +0200 (Tue, 05 May 2009)");
  script_cve_id("CVE-2008-1897", "CVE-2008-2119", "CVE-2008-3263", "CVE-2008-3264", "CVE-2008-3903", "CVE-2008-5558", "CVE-2009-0041");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_name("Gentoo Security Advisory GLSA 200905-01 (asterisk)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"Multiple vulnerabilities have been found in Asterisk allowing for Denial of
    Service and username disclosure.");
  script_tag(name:"solution", value:"All Asterisk users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=net-misc/asterisk-1.2.32'");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200905-01");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=218966");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=224835");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=232696");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=232698");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=237476");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=250748");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=254304");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200905-01.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"net-misc/asterisk", unaffected: make_list("ge 1.2.32"), vulnerable: make_list("lt 1.2.32"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
