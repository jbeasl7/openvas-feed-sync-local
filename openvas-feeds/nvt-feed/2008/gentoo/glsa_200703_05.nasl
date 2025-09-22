# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.58064");
  script_version("2023-07-19T05:05:15+0000");
  script_cve_id("CVE-2006-2775", "CVE-2006-2776", "CVE-2006-2778", "CVE-2006-2779",
                "CVE-2006-2780", "CVE-2006-2781", "CVE-2006-2782", "CVE-2006-2783",
                "CVE-2006-2784", "CVE-2006-2785", "CVE-2006-2786", "CVE-2006-2787",
                "CVE-2006-2788", "CVE-2006-2777");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Gentoo Security Advisory GLSA 200703-05 (mozilla)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"Several vulnerabilities exist in the Mozilla Suite, which is no longer
supported by the Mozilla project.");
  script_tag(name:"solution", value:"The Mozilla Suite is no longer supported and has been masked after some
necessary changes on all the other ebuilds which used to depend on it.
Mozilla Suite users should unmerge www-client/mozilla or
www-client/mozilla-bin, and switch to a supported product, like SeaMonkey,
Thunderbird or Firefox.


    # emerge --unmerge 'www-client/mozilla'

    # emerge --unmerge 'www-client/mozilla-bin'");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200703-05");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/18228");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=135257");
  script_xref(name:"URL", value:"http://www.mozilla.org/projects/security/known-vulnerabilities.html#Mozilla");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200703-05.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"www-client/mozilla", unaffected: make_list(), vulnerable: make_list("le 1.7.13"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"www-client/mozilla-bin", unaffected: make_list(), vulnerable: make_list("le 1.7.13"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
