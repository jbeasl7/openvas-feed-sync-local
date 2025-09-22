# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:phpbb:phpbb";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113005");
  script_version("2024-03-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-03-01 14:37:10 +0000 (Fri, 01 Mar 2024)");
  script_tag(name:"creation_date", value:"2017-09-28 11:56:33 +0200 (Thu, 28 Sep 2017)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-09-27 17:42:00 +0000 (Wed, 27 Sep 2017)");
  script_cve_id("CVE-2015-3880");
  script_name("phpBB Open Redirect Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("phpbb_detect.nasl");
  script_mandatory_keys("phpBB/installed");

  script_xref(name:"URL", value:"https://github.com/phpbb/phpbb/commit/1a3350619f428d9d69d196c52128727e27ef2f04");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/74592");
  script_xref(name:"URL", value:"https://wiki.phpbb.com/Release_Highlights/3.0.14");
  script_xref(name:"URL", value:"https://wiki.phpbb.com/Release_Highlights/3.1.4");
  script_xref(name:"URL", value:"https://www.phpbb.com/community/viewtopic.php?f=14&t=2313941");

  script_tag(name:"summary", value:"Open redirect vulnerability in phpBB before 3.0.14 and 3.1.x before 3.1.4.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Successful exploitation allows remote attackers to redirect users of Google Chrome
  to arbitrary web sites and conduct phishing attacks via unspecified vectors.");

  script_tag(name:"affected", value:"phpBB versions before 3.0.14 and versions 3.1.x before 3.1.4.");

  script_tag(name:"solution", value:"Update to version 3.0.14 or 3.1.4 respectively.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

vers = infos["version"];
path = infos["location"];

if( version_in_range( version:vers, test_version:"3.1.0", test_version2:"3.1.3" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"3.1.4", install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

if( version_is_less( version:vers, test_version:"3.0.14" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"3.0.14", install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
