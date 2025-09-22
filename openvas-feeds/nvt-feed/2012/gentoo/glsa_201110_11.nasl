# SPDX-FileCopyrightText: 2012 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.70774");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2011-0558", "CVE-2011-0559", "CVE-2011-0560", "CVE-2011-0561", "CVE-2011-0571", "CVE-2011-0572", "CVE-2011-0573", "CVE-2011-0574", "CVE-2011-0575", "CVE-2011-0577", "CVE-2011-0578", "CVE-2011-0579", "CVE-2011-0589", "CVE-2011-0607", "CVE-2011-0608", "CVE-2011-0609", "CVE-2011-0611", "CVE-2011-0618", "CVE-2011-0619", "CVE-2011-0620", "CVE-2011-0621", "CVE-2011-0622", "CVE-2011-0623", "CVE-2011-0624", "CVE-2011-0625", "CVE-2011-0626", "CVE-2011-0627", "CVE-2011-0628", "CVE-2011-2107", "CVE-2011-2110", "CVE-2011-2135", "CVE-2011-2125", "CVE-2011-2130", "CVE-2011-2134", "CVE-2011-2136", "CVE-2011-2137", "CVE-2011-2138", "CVE-2011-2139", "CVE-2011-2140", "CVE-2011-2414", "CVE-2011-2415", "CVE-2011-2416", "CVE-2011-2417", "CVE-2011-2424", "CVE-2011-2425", "CVE-2011-2426", "CVE-2011-2427", "CVE-2011-2428", "CVE-2011-2429", "CVE-2011-2430", "CVE-2011-2444");
  script_version("2024-02-02T05:06:11+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:11 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-02 02:39:19 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"creation_date", value:"2012-02-12 10:04:39 -0500 (Sun, 12 Feb 2012)");
  script_name("Gentoo Security Advisory GLSA 201110-11 (Adobe Flash Player)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"Multiple vulnerabilities in Adobe Flash Player might allow remote
    attackers to execute arbitrary code or cause a Denial of Service.");
  script_tag(name:"solution", value:"All Adobe Flash Player users should upgrade to the latest version:

      # emerge --sync
      # emerge --ask --oneshot --verbose
      '>=www-plugins/adobe-flash-10.3.183.10'");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20201110-11");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=354207");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=359019");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=363179");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=367031");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=370215");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=372899");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=378637");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=384017");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/advisories/apsa11-01.html");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/advisories/apsa11-02.html");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb11-02.html");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb11-12.html");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb11-13.html");
  script_xref(name:"URL", value:"https://www.adobe.com/support/security/bulletins/apsb11-21.html");
  script_xref(name:"URL", value:"https://www.adobe.com/support/security/bulletins/apsb11-26.html");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 201110-11.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
if((res = ispkgvuln(pkg:"www-plugins/adobe-flash", unaffected: make_list("ge 10.3.183.10"), vulnerable: make_list("lt 10.3.183.10"))) != NULL ) {
    report += res;
}

if(report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
