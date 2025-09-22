# SPDX-FileCopyrightText: 2010 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.66641");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-01-07 13:59:33 +0100 (Thu, 07 Jan 2010)");
  script_cve_id("CVE-2008-5498", "CVE-2008-5514", "CVE-2008-5557", "CVE-2008-5624", "CVE-2008-5625", "CVE-2008-5658", "CVE-2008-5814", "CVE-2008-5844", "CVE-2008-7002", "CVE-2009-0754", "CVE-2009-1271", "CVE-2009-1272", "CVE-2009-2626", "CVE-2009-2687", "CVE-2009-3291");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Gentoo Security Advisory GLSA 201001-03 (php)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"Multiple vulnerabilities were found in PHP, the worst of which leading to
    the remote execution of arbitrary code.");
  script_tag(name:"solution", value:"All PHP users should upgrade to the latest version. As PHP is
    statically linked against a vulnerable version of the c-client library
    when the imap or kolab USE flag is enabled (GLSA 200911-03), users
    should upgrade net-libs/c-client beforehand:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=net-libs/c-client-2007e'
    # emerge --ask --oneshot --verbose '>=dev-lang/php-5.2.12'");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20201001-03");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=249875");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=255121");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=260576");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=261192");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=266125");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=274670");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=280602");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=285434");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=292132");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=293888");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=297369");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=297370");
  script_xref(name:"URL", value:"http://www.gentoo.org/security/en/glsa/glsa-200911-03.xml");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 201001-03.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"dev-lang/php", unaffected: make_list("ge 5.2.12"), vulnerable: make_list("lt 5.2.12"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
