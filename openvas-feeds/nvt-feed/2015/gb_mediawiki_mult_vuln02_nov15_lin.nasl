# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mediawiki:mediawiki";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806633");
  script_version("2024-07-16T05:05:43+0000");
  script_cve_id("CVE-2013-6451", "CVE-2013-6452", "CVE-2013-6453", "CVE-2013-6454", "CVE-2013-6472");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-07-16 05:05:43 +0000 (Tue, 16 Jul 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-01-30 18:32:00 +0000 (Thu, 30 Jan 2020)");
  script_tag(name:"creation_date", value:"2015-11-26 16:46:38 +0530 (Thu, 26 Nov 2015)");
  script_name("MediaWiki Multiple Vulnerabilities -02 (Nov 2015) - Linux");

  script_tag(name:"summary", value:"MediaWiki is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An error which displays some information about deleted pages in the log
  API, enhanced RecentChanges, and user watchlists.

  - An error in CSS whose sanitization did not filter -o-link attributes.

  - An error leading SVG sanitization to bypass when the XML was considered
  invalid.

  - An error in SVG files upload that could lead to include external stylesheets
  in upload.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to conduct XSS attacks, gain access to sensitive information and
  have other some unspecified impact.");

  script_tag(name:"affected", value:"MediaWiki before 1.19.10, 1.2x before 1.21.4,
  and 1.22.x before 1.22.1 on Linux.");

  script_tag(name:"solution", value:"Upgrade to version 1.19.10 or 1.21.4 or
  1.22.1 or later.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://lists.wikimedia.org/pipermail/mediawiki-announce/2014-January/000138.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65003");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_mediawiki_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("mediawiki/detected", "Host/runs_unixoide");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!vers = get_app_version(cpe:CPE, port:port))
  exit(0);

if(version_is_less(version:vers, test_version:"1.19.10")) {
  fix = "1.19.10";
  VULN = TRUE ;
}

else if(version_in_range(version:vers, test_version:"1.20", test_version2:"1.21.3")) {
  fix = "1.21.4";
  VULN = TRUE ;
}

else if(version_is_equal(version:vers, test_version:"1.22.0")) {
  fix = "1.22.1";
  VULN = TRUE ;
}

if(VULN) {
  report = report_fixed_ver(installed_version:vers, fixed_version:fix);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
