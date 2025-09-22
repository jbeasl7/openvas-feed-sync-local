# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:egroupware:egroupware";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108066");
  script_version("2024-07-12T15:38:44+0000");
  script_tag(name:"last_modification", value:"2024-07-12 15:38:44 +0000 (Fri, 12 Jul 2024)");
  script_tag(name:"creation_date", value:"2017-02-01 09:00:00 +0100 (Wed, 01 Feb 2017)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");

  script_cve_id("CVE-2014-2987", "CVE-2014-2988");

  script_tag(name:"qod_type", value:"remote_banner_unreliable"); # Might only be the major version

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("EGroupware Multiple Vulnerabilities (Feb 2017)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_egroupware_http_detect.nasl");
  script_mandatory_keys("egroupware/detected");

  script_tag(name:"summary", value:"EGroupware is prone to multiple cross-site request forgery
  (CSRF) and remote PHP code execution vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Successfully exploiting these issues will allow attackers to
  execute arbitrary code within the context of the application.");

  script_tag(name:"affected", value:"EGroupware Enterprise Line (EPL) before version 11.1.20140505,
  EGroupware Community Edition before version 1.8.007.20140506 and EGroupware before version
  14.1 beta.");

  script_tag(name:"solution", value:"Update to version 11.1.20140505 (EPL), 1.8.007.20140506
  (Community Edition), 14.1 beta or later.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67303");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67409");

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

# Version is only exposed as 1.8.007 without the date
if( version_is_less( version:version, test_version:"1.8.007" ) )
  fix = "1.8.007.20140506";

# CVE says the vulnerable EPL version is 1.1.20140505 but the "real" EPL versions are 9.2 - 11.1
if( version_in_range( version:version, test_version:"9", test_version2:"11.1.20140416" ) )
  fix = "11.1.20140505";

if( fix ) {
  report = report_fixed_ver( installed_version:version, fixed_version:fix, install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
