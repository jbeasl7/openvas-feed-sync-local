# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:zohocorp:manageengine_servicedesk_plus";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801962");
  script_version("2025-06-12T05:40:18+0000");
  script_tag(name:"last_modification", value:"2025-06-12 05:40:18 +0000 (Thu, 12 Jun 2025)");
  script_tag(name:"creation_date", value:"2011-08-04 10:01:53 +0200 (Thu, 04 Aug 2011)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("ManageEngine ServiceDesk Plus <= 8.0 Build 8013 Multiple XSS Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_manageengine_servicedesk_plus_consolidation.nasl");
  script_mandatory_keys("manageengine/servicedesk_plus/detected");

  script_xref(name:"URL", value:"https://web.archive.org/web/20210127065209/http://www.securityfocus.com/bid/48928");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/17586");
  script_xref(name:"URL", value:"https://exchange.xforce.ibmcloud.com/vulnerabilities/68717");
  script_xref(name:"URL", value:"http://sebug.net/exploit/20793/");

  script_tag(name:"summary", value:"ManageEngine ServiceDesk Plus is prone to multiple cross-site
  scripting (XSS) vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to an error in:

  - 'SetUpWizard.do' when handling configuration wizard (add new technician) action via 'Name'
  parameter.

  - 'SiteDef.do' when handling add a new site action via 'Site name' parameter.

  - 'GroupResourcesDef.do' when handling add a create group action via 'Group Name' parameter.

  - 'LicenseAgreement.do' when handling add a new license agreement action via 'Agreement Number'
  parameter.

  - 'ManualNodeAddition.do' when handling server configuration (computer) action via 'Name'
  parameter.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary
  HTML and script code in a user's browser session in the context of a vulnerable site. This may
  allow an attacker to steal cookie-based authentications and launch further attacks.");

  script_tag(name:"affected", value:"ManageEngine ServiceDesk Plus 8.0 Build 8013 and prior.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"WillNotFix");

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

if( version_is_less_equal( version:version, test_version:"8.0b8013" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"None", install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 0 );
