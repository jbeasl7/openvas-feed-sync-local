# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:joomla:joomla";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105487");
  script_version("2025-09-19T15:40:40+0000");
  script_cve_id("CVE-2015-8562");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-09-19 15:40:40 +0000 (Fri, 19 Sep 2025)");
  script_tag(name:"creation_date", value:"2015-12-17 11:34:17 +0100 (Thu, 17 Dec 2015)");
  script_name("Joomla! 1.5.0 < 3.4.6 RCE Vulnerability - Version Check");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_dependencies("joomla_detect.nasl");
  script_mandatory_keys("joomla/installed");

  script_xref(name:"URL", value:"https://developer.joomla.org/security-centre/630-20151214-core-remote-code-execution-vulnerability.html");
  script_xref(name:"URL", value:"https://web.archive.org/web/20210120182848/http://www.securityfocus.com/bid/79195");

  script_tag(name:"summary", value:"Joomla! is prone to a remote code execution (RCE)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Browser information is not filtered properly while saving the
  session values into the database which leads to a Remote Code Execution vulnerability.");

  script_tag(name:"impact", value:"Successfully exploiting this issue allows attackers to execute
  arbitrary code in the context of the affected application.");

  script_tag(name:"affected", value:"Joomla! versions 1.5.0 through 3.4.5.");

  script_tag(name:"solution", value:"Update to version 3.4.6 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
path = infos["location"];

if( version_in_range( version:version, test_version:"1.5.0", test_version2:"3.4.5" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"3.4.6", install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
