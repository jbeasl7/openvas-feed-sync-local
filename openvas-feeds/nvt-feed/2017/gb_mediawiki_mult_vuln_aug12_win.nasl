# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mediawiki:mediawiki";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112114");
  script_version("2024-07-16T05:05:43+0000");
  script_cve_id("CVE-2012-4377", "CVE-2012-4378", "CVE-2012-4379", "CVE-2012-4380", "CVE-2012-4382");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2024-07-16 05:05:43 +0000 (Tue, 16 Jul 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-10-31 22:08:00 +0000 (Tue, 31 Oct 2017)");
  script_tag(name:"creation_date", value:"2017-11-08 13:58:17 +0100 (Wed, 08 Nov 2017)");
  script_name("MediaWiki Multiple Vulnerabilities (Aug 2012) - Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_mediawiki_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("mediawiki/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"MediaWiki is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - a Cross-site scripting (XSS) vulnerability that allows remote attackers to inject arbitrary web script or HTML via a File: link to a nonexistent image.

  - multiple cross-site scripting (XSS) vulnerabilities, when unspecified JavaScript gadgets are used, allow remote attackers
  to inject arbitrary web script or HTML via the userlang parameter to w/index.php.

  - MediaWiki not sending a restrictive X-Frame-Options HTTP header, which allows remote attackers to conduct clickjacking attacks via an embedded API response in an IFRAME element.

  - MediaWiki allowing remote attackers to bypass GlobalBlocking extension IP address blocking and thus creating an account via unspecified vectors.

  - MediaWiki not properly protecting user block metadata, which allows remote administrators to read a user block reason via a reblock attempt.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to conduct XSS attacks, affect the application's integrity and
  have other some unspecified impact.");

  script_tag(name:"affected", value:"MediaWiki before 1.18.5, and 1.19.x before 1.19.2");

  script_tag(name:"solution", value:"Upgrade to version 1.18.5 or 1.19.2 or later.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( version_is_less( version:vers, test_version:"1.18.5" ) ) {
  fix = "1.18.5";
  VULN = TRUE;
}

else if( version_in_range( version:vers, test_version:"1.19.0", test_version2:"1.19.1" ) ) {
  fix = "1.19.2";
  VULN = TRUE;
}

if( VULN ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:fix );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
