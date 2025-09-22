# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:phpmyadmin:phpmyadmin";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800381");
  script_version("2024-07-17T05:05:38+0000");
  script_tag(name:"last_modification", value:"2024-07-17 05:05:38 +0000 (Wed, 17 Jul 2024)");
  script_tag(name:"creation_date", value:"2009-04-20 14:33:23 +0200 (Mon, 20 Apr 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-16 17:48:50 +0000 (Tue, 16 Jul 2024)");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2009-1148", "CVE-2009-1149", "CVE-2009-1150", "CVE-2009-1151");
  script_name("phpMyAdmin 2.11.x < 2.11.9.4 / 3.0.x < 3.1.3 Multiple Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_phpmyadmin_http_detect.nasl");
  script_mandatory_keys("phpMyAdmin/installed");

  script_xref(name:"URL", value:"http://secunia.com/advisories/34430");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34236");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34251");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34253");
  script_xref(name:"URL", value:"http://www.phpmyadmin.net/home_page/security/PMASA-2009-1.php");
  script_xref(name:"URL", value:"http://www.phpmyadmin.net/home_page/security/PMASA-2009-2.php");
  script_xref(name:"URL", value:"http://www.phpmyadmin.net/home_page/security/PMASA-2009-3.php");

  script_tag(name:"impact", value:"Successful exploitation will let the attacker cause XSS, Directory Traversal
  attacks or can injection malicious PHP Codes to gain sensitive information about the remote host.");

  script_tag(name:"affected", value:"phpMyAdmin version 2.11.x to 2.11.9.4 and 3.0.x to 3.1.3.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - BLOB streaming feature in 'bs_disp_as_mime_type.php' causes CRLF Injection
  which lets the attacker inject arbitrary data in the HTTP headers through
  the 'c_type' and 'file_type' parameters.

  - XSS Vulnerability in 'display_export.lib.php' as its not sanitizing the
  'pma_db_filename_template' parameter.

  - Static code injection vulnerability in 'setup.php' which can be used to
  inject PHP Codes.

  - Filename 'bs_disp_as_mime_type.php' which is not sanitizing user supplied
  inputs in the filename variable which causes directory traversal attacks.");

  script_tag(name:"summary", value:"phpMyAdmin is prone to multiple vulnerabilities.");

  script_tag(name:"solution", value:"Upgrade to version 2.11.9.5 or 3.1.3.1 or later.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit( 0);

if( version_in_range( version:vers, test_version:"2.11", test_version2:"2.11.9.4" ) ||
    version_in_range( version:vers, test_version:"3.0", test_version2:"3.1.3" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"2.11.9.5/3.1.3.1" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
