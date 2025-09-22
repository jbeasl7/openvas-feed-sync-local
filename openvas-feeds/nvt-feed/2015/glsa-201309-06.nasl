# SPDX-FileCopyrightText: 2015 Eero Volotinen
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.121020");
  script_version("2024-11-29T15:40:53+0000");
  script_tag(name:"creation_date", value:"2015-09-29 11:25:47 +0300 (Tue, 29 Sep 2015)");
  script_tag(name:"last_modification", value:"2024-11-29 15:40:53 +0000 (Fri, 29 Nov 2024)");
  script_name("Gentoo Security Advisory GLSA 201309-06");
  script_tag(name:"insight", value:"Multiple unspecified vulnerabilities have been discovered in Adobe Flash Player. Please review the CVE identifiers referenced below for details.");
  script_tag(name:"solution", value:"Update the affected packages to the latest available version.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://security.gentoo.org/glsa/201309-06");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2012-5248", "CVE-2012-5249", "CVE-2012-5250", "CVE-2012-5251", "CVE-2012-5252", "CVE-2012-5253", "CVE-2012-5254", "CVE-2012-5255", "CVE-2012-5256", "CVE-2012-5257", "CVE-2012-5258", "CVE-2012-5259", "CVE-2012-5260", "CVE-2012-5261", "CVE-2012-5262", "CVE-2012-5263", "CVE-2012-5264", "CVE-2012-5265", "CVE-2012-5266", "CVE-2012-5267", "CVE-2012-5268", "CVE-2012-5269", "CVE-2012-5270", "CVE-2012-5271", "CVE-2012-5272", "CVE-2012-5274", "CVE-2012-5275", "CVE-2012-5276", "CVE-2012-5277", "CVE-2012-5278", "CVE-2012-5279", "CVE-2012-5280", "CVE-2012-5676", "CVE-2012-5677", "CVE-2012-5678", "CVE-2013-0504", "CVE-2013-0630", "CVE-2013-0633", "CVE-2013-0634", "CVE-2013-0637", "CVE-2013-0638", "CVE-2013-0639", "CVE-2013-0642", "CVE-2013-0643", "CVE-2013-0644", "CVE-2013-0645", "CVE-2013-0646", "CVE-2013-0647", "CVE-2013-0648", "CVE-2013-0649", "CVE-2013-0650", "CVE-2013-1365", "CVE-2013-1366", "CVE-2013-1367", "CVE-2013-1368", "CVE-2013-1369", "CVE-2013-1370", "CVE-2013-1371", "CVE-2013-1372", "CVE-2013-1373", "CVE-2013-1374", "CVE-2013-1375", "CVE-2013-1378", "CVE-2013-1379", "CVE-2013-1380", "CVE-2013-2555", "CVE-2013-2728", "CVE-2013-3343", "CVE-2013-3344", "CVE-2013-3345", "CVE-2013-3347", "CVE-2013-3361", "CVE-2013-3362", "CVE-2013-3363", "CVE-2013-5324");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-09-19 19:51:57 +0000 (Thu, 19 Sep 2024)");
  script_tag(name:"qod_type", value:"package");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"summary", value:"Gentoo Linux Local Security Checks GLSA 201309-06");
  script_copyright("Copyright (C) 2015 Eero Volotinen");
  script_family("Gentoo Local Security Checks");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-gentoo.inc");

res = "";
report = "";

if((res=ispkgvuln(pkg:"www-plugins/adobe-flash", unaffected: make_list("ge 11.2.202.310"), vulnerable: make_list("lt 11.2.202.310"))) != NULL) {
  report += res;
}

if(report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
