# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.60620");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
  script_cve_id("CVE-2007-5707", "CVE-2007-5708", "CVE-2008-0658");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_name("Gentoo Security Advisory GLSA 200803-28 (openldap)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"Multiple Denial of Service vulnerabilities have been reported in OpenLDAP.");
  script_tag(name:"solution", value:"All OpenLDAP users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=net-nds/openldap-2.3.41'");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200803-28");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=197446");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=209677");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200803-28.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"net-nds/openldap", unaffected: make_list("ge 2.3.41"), vulnerable: make_list("lt 2.3.41"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
