# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:php:php";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803341");
  script_version("2024-02-08T05:05:59+0000");
  script_cve_id("CVE-2012-1172");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-08 05:05:59 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2013-03-21 16:27:46 +0530 (Thu, 21 Mar 2013)");
  script_name("PHP Multiple Vulnerabilities - 01 (Mar 2013) - Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("secpod_php_smb_login_detect.nasl", "gb_php_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("php/detected", "Host/runs_windows");

  script_xref(name:"URL", value:"http://www.php.net/ChangeLog-5.php");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/53403");
  script_xref(name:"URL", value:"http://cxsecurity.com/cveshow/CVE-2012-1172");
  script_xref(name:"URL", value:"http://secunia.com/advisories/cve_reference/CVE-2012-1172");

  script_tag(name:"summary", value:"PHP is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Flaw due to insufficient validation of file-upload implementation in
  rfc1867.c and it does not handle invalid '[' characters in name values.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to retrieve, corrupt or upload
  arbitrary files, or can cause denial of service via corrupted $_FILES indexes.");

  script_tag(name:"affected", value:"PHP version before 5.4.0");

  script_tag(name:"solution", value:"Update to PHP 5.4.0 or later.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( isnull( port = get_app_port( cpe:CPE ) ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_is_less( version:vers, test_version:"5.4.0" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"5.4.0" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
