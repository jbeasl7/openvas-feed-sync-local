# SPDX-FileCopyrightText: 2015 Eero Volotinen
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.121341");
  script_version("2024-07-04T05:05:37+0000");
  script_tag(name:"creation_date", value:"2015-09-29 11:28:27 +0300 (Tue, 29 Sep 2015)");
  script_tag(name:"last_modification", value:"2024-07-04 05:05:37 +0000 (Thu, 04 Jul 2024)");
  script_name("Gentoo Security Advisory GLSA 201502-02");
  script_tag(name:"insight", value:"Multiple vulnerabilities have been discovered in Adobe Flash Player. Please review the CVE identifiers referenced below for details.");
  script_tag(name:"solution", value:"Update the affected packages to the latest available version.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://security.gentoo.org/glsa/201502-02");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2015-0301", "CVE-2015-0302", "CVE-2015-0303", "CVE-2015-0304", "CVE-2015-0305", "CVE-2015-0306", "CVE-2015-0307", "CVE-2015-0308", "CVE-2015-0309", "CVE-2015-0310", "CVE-2015-0311", "CVE-2015-0314", "CVE-2015-0315", "CVE-2015-0316", "CVE-2015-0317", "CVE-2015-0318", "CVE-2015-0319", "CVE-2015-0320", "CVE-2015-0321", "CVE-2015-0322", "CVE-2015-0323", "CVE-2015-0324", "CVE-2015-0325", "CVE-2015-0326", "CVE-2015-0327", "CVE-2015-0328", "CVE-2015-0329", "CVE-2015-0330");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-02 17:41:45 +0000 (Tue, 02 Jul 2024)");
  script_tag(name:"qod_type", value:"package");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"summary", value:"Gentoo Linux Local Security Checks GLSA 201502-02");
  script_copyright("Copyright (C) 2015 Eero Volotinen");
  script_family("Gentoo Local Security Checks");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-gentoo.inc");

res = "";
report = "";

if((res=ispkgvuln(pkg:"www-plugins/adobe-flash", unaffected: make_list("ge 11.2.202.442"), vulnerable: make_list("lt 11.2.202.442"))) != NULL) {
  report += res;
}

if(report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
