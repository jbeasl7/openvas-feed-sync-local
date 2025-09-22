# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.60504");
  script_version("2024-07-01T05:05:38+0000");
  script_tag(name:"last_modification", value:"2024-07-01 05:05:38 +0000 (Mon, 01 Jul 2024)");
  script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2007-1199", "CVE-2007-5659", "CVE-2007-5663", "CVE-2007-5666", "CVE-2008-0655", "CVE-2008-0667", "CVE-2008-0726");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-06-28 14:15:34 +0000 (Fri, 28 Jun 2024)");
  script_name("Gentoo Security Advisory GLSA 200803-01 (acroread)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"Adobe Acrobat Reader is vulnerable to remote code execution, Denial of
Service, and cross-site request forgery attacks.");
  script_tag(name:"solution", value:"All Adobe Acrobat Reader users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=app-text/acroread-8.1.2'");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200803-01");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=170177");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200803-01.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"app-text/acroread", unaffected: make_list("ge 8.1.2"), vulnerable: make_list("lt 8.1.2"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
