# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.66602");
  script_version("2024-02-14T05:07:39+0000");
  script_tag(name:"last_modification", value:"2024-02-14 05:07:39 +0000 (Wed, 14 Feb 2024)");
  script_tag(name:"creation_date", value:"2009-12-30 21:58:43 +0100 (Wed, 30 Dec 2009)");
  script_cve_id("CVE-2007-5380", "CVE-2007-6077", "CVE-2008-4094", "CVE-2008-7248", "CVE-2009-2422", "CVE-2009-3009", "CVE-2009-3086", "CVE-2009-4214");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-13 17:44:31 +0000 (Tue, 13 Feb 2024)");
  script_name("Gentoo Security Advisory GLSA 200912-02 (rails)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"Multiple vulnerabilities have been discovered in Rails, the worst of which
    leading to the execution of arbitrary SQL statements.");
  script_tag(name:"solution", value:"All Ruby on Rails 2.3.x users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=dev-ruby/rails-2.3.5'

All Ruby on Rails 2.2.x users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '=dev-ruby/rails-2.2.3-r1'

NOTE: All applications using Ruby on Rails should also be configured to
    use the latest version available by running 'rake rails:update' inside
    the application directory.");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200912-02");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=200159");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=237385");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=247549");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=276279");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=283396");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=294797");
  script_xref(name:"URL", value:"http://www.gentoo.org/security/en/glsa/glsa-200711-17.xml");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200912-02.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"dev-ruby/rails", unaffected: make_list("ge 2.3.5", "rge 2.2.3-r1"), vulnerable: make_list("lt 2.2.2"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
