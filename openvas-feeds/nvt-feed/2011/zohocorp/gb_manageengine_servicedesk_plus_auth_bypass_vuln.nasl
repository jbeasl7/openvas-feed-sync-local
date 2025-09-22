# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:zohocorp:manageengine_servicedesk_plus";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801984");
  script_version("2025-06-12T05:40:18+0000");
  script_tag(name:"last_modification", value:"2025-06-12 05:40:18 +0000 (Thu, 12 Jun 2025)");
  script_tag(name:"creation_date", value:"2011-09-16 17:22:17 +0200 (Fri, 16 Sep 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2011-1509");
  script_name("ManageEngine ServiceDesk Plus <= 8.0 Build 8013 Authentication Bypass Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_manageengine_servicedesk_plus_consolidation.nasl");
  script_mandatory_keys("manageengine/servicedesk_plus/detected");

  script_xref(name:"URL", value:"https://packetstorm.news/files/id/105123");
  script_xref(name:"URL", value:"https://www.coresecurity.com/core-labs/advisories/multiples-vulnerabilities-manageengine-sdp");

  script_tag(name:"summary", value:"ManageEngine ServiceDesk Plus is prone to an authentication
  bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an error in authentication process, User
  passwords are pseudo encrypted and locally stored in user cookies. Having Javascript code encrypt
  and decrypt passwords in Login.js file.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to get user names and
  passwords of registered users. This may allow an attacker to steal cookie-based  authentications
  and launch further attacks.");

  script_tag(name:"affected", value:"ManageEngine ServiceDesk Plus 8.0 Build 8013 and prior.");

  script_tag(name:"solution", value:"Update to version 8.0 Build 8014 or later.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( isnull( port = get_app_port( cpe:CPE ) ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
path = infos["location"];

if( version_is_less( version:version, test_version:"8.0b8014" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"8.0 (Build 8014)", install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
