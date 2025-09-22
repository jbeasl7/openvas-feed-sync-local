# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:phpipam:phpipam";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107047");
  script_version("2023-10-13T05:06:09+0000");
  script_tag(name:"last_modification", value:"2023-10-13 05:06:09 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2016-09-12 06:40:16 +0200 (Mon, 12 Sep 2016)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("phpIPAM <= 1.2.1 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_phpipam_http_detect.nasl");
  script_mandatory_keys("phpipam/detected");

  script_tag(name:"summary", value:"phpIPAM is prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"phpIPAM version 1.2.1 suffers from cross site scripting and remote
  SQL injection vulnerabilities.");

  script_tag(name:"impact", value:"Allows unauthorized disclosure of information, allows unauthorized
  modification and allows disruption of service.");

  script_tag(name:"affected", value:"phpIPAM version 1.2.1 and prior.");

  script_tag(name:"solution", value:"Update to version 1.3 or later.");

  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/138603/PHPIPAM-1.2.1-Cross-Site-Scripting-SQL-Injection.html");
  script_xref(name:"URL", value:"https://phpipam.net/documents/changelog/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less_equal( version:version, test_version:"1.2.1" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"1.3", install_path: location);
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 0 );
