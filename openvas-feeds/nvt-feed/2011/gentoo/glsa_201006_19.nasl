# SPDX-FileCopyrightText: 2011 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.69022");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-03-09 05:54:11 +0100 (Wed, 09 Mar 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2008-4437", "CVE-2008-6098", "CVE-2009-0481", "CVE-2009-0482", "CVE-2009-0483", "CVE-2009-0484", "CVE-2009-0485", "CVE-2009-0486", "CVE-2009-1213", "CVE-2009-3125", "CVE-2009-3165", "CVE-2009-3166", "CVE-2009-3387", "CVE-2009-3989");
  script_name("Gentoo Security Advisory GLSA 201006-19 (bugzilla)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"Bugzilla is prone to multiple medium severity vulnerabilities.");
  script_tag(name:"solution", value:"All Bugzilla users should upgrade to an unaffected version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=www-apps/bugzilla-3.2.6'

Bugzilla 2.x and 3.0 have reached their end of life. There will be no
    more security updates. All Bugzilla 2.x and 3.0 users should update to
    a supported Bugzilla 3.x version.");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20201006-19");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=239564");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=258592");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=264572");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=284824");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=303437");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=303725");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 201006-19.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"www-apps/bugzilla", unaffected: make_list("ge 3.2.6"), vulnerable: make_list("lt 3.2.6"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
