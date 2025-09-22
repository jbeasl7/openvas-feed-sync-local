# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.61860");
  script_version("2024-02-05T05:05:38+0000");
  script_tag(name:"last_modification", value:"2024-02-05 05:05:38 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"creation_date", value:"2008-11-19 16:52:57 +0100 (Wed, 19 Nov 2008)");
  script_cve_id("CVE-2008-0599", "CVE-2008-0674", "CVE-2008-1384", "CVE-2008-2050", "CVE-2008-2051", "CVE-2008-2107", "CVE-2008-2108", "CVE-2008-2371", "CVE-2008-2665", "CVE-2008-2666", "CVE-2008-2829", "CVE-2008-3658", "CVE-2008-3659", "CVE-2008-3660");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-02 13:52:57 +0000 (Fri, 02 Feb 2024)");
  script_name("Gentoo Security Advisory GLSA 200811-05 (php)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"PHP contains several vulnerabilities including buffer and integer overflows
which could lead to the remote execution of arbitrary code.");
  script_tag(name:"solution", value:"All PHP users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=dev-lang/php-5.2.6-r6'");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200811-05");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=209148");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=212211");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=215266");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=228369");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=230575");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=234102");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200811-05.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"dev-lang/php", unaffected: make_list("ge 5.2.6-r6"), vulnerable: make_list("lt 5.2.6-r6"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
