# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112726");
  script_version("2024-07-16T05:05:43+0000");
  script_tag(name:"last_modification", value:"2024-07-16 05:05:43 +0000 (Tue, 16 Jul 2024)");
  script_tag(name:"creation_date", value:"2020-04-06 06:54:11 +0000 (Mon, 06 Apr 2020)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MediaWiki 1.34.0 URL Redirect Vulnerability - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_mediawiki_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("mediawiki/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"MediaWiki is prone to a URL redirect vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"It is possible to manipulate the redirect location of the logout button to target a different URL.");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to
  redirect the user to a different URL instead of having them logout of the application.");

  script_tag(name:"affected", value:"MediaWiki version 1.34.0.");

  script_tag(name:"solution", value:"Update to version 1.34.1.");

  script_xref(name:"URL", value:"https://phabricator.wikimedia.org/T232932");
  script_xref(name:"URL", value:"https://lists.wikimedia.org/pipermail/wikitech-l/2020-March/093243.html");

  exit(0);
}

CPE = "cpe:/a:mediawiki:mediawiki";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_equal( version: version, test_version: "1.34.0" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.34.1", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
