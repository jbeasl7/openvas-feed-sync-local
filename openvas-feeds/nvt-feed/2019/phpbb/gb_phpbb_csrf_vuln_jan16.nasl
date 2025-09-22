# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:phpbb:phpbb";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108656");
  script_version("2025-09-17T05:39:26+0000");
  script_tag(name:"last_modification", value:"2025-09-17 05:39:26 +0000 (Wed, 17 Sep 2025)");
  script_tag(name:"creation_date", value:"2019-10-01 05:49:54 +0000 (Tue, 01 Oct 2019)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-11-21 13:34:00 +0000 (Thu, 21 Nov 2019)");
  script_cve_id("CVE-2019-16993");
  script_name("phpBB < 3.1.7-PL1 CSRF Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("phpbb_detect.nasl");
  script_mandatory_keys("phpBB/installed");

  script_tag(name:"summary", value:"phpBB is prone to a CSRF vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The includes/acp/acp_bbcodes.php has improper verification of a CSRF
  token on the BBCode page in the Administration Control Panel. An actual CSRF attack is possible if an
  attacker also manages to retrieve the session id of a reauthenticated administrator prior to targeting them.");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to
  trick users into carrying out unwanted actions.");

  script_tag(name:"affected", value:"phpBB versions before 3.1.7-PL1.");

  script_tag(name:"solution", value:"Update to version 3.1.7-PL1 or later.");

  script_xref(name:"URL", value:"https://www.phpbb.com/community/viewtopic.php?t=2352606");
  script_xref(name:"URL", value:"https://github.com/phpbb/phpbb/commit/18abef716ecf42a35416444f3f84f5459d573789");

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

if( version_is_less( version:vers, test_version:"3.1.7.PL1" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"3.1.8 PL1", install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
