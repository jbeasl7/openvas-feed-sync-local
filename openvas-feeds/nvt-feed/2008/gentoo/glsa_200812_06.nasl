# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.61945");
  script_version("2024-02-05T05:05:38+0000");
  script_tag(name:"last_modification", value:"2024-02-05 05:05:38 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"creation_date", value:"2008-12-03 18:25:22 +0100 (Wed, 03 Dec 2008)");
  script_cve_id("CVE-2008-3281", "CVE-2008-3529", "CVE-2008-4409", "CVE-2008-4225", "CVE-2008-4226");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-02 15:02:14 +0000 (Fri, 02 Feb 2024)");
  script_name("Gentoo Security Advisory GLSA 200812-06 (libxml2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"Multiple vulnerabilities in libxml2 might lead to execution of arbitrary
code or Denial of Service.");
  script_tag(name:"solution", value:"All libxml2 users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=dev-libs/libxml2-2.7.2-r1'");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200812-06");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=234099");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=237806");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=239346");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=245960");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200812-06.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"dev-libs/libxml2", unaffected: make_list("ge 2.7.2-r1"), vulnerable: make_list("lt 2.7.2-r1"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
