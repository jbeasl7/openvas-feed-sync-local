# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112724");
  script_version("2024-07-16T05:05:43+0000");
  script_tag(name:"last_modification", value:"2024-07-16 05:05:43 +0000 (Tue, 16 Jul 2024)");
  script_tag(name:"creation_date", value:"2020-04-06 06:54:11 +0000 (Mon, 06 Apr 2020)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-06-02 19:31:00 +0000 (Tue, 02 Jun 2020)");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2020-10959", "CVE-2020-10960");

  script_name("MediaWiki 1.31.x < 1.31.7, 1.33.x < 1.33.3 and 1.34.0 Multiple Vulnerabilities - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_mediawiki_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("mediawiki/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"MediaWiki is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - resources/src/mediawiki.page.ready/ready.js allows remote attackers to force a logout and external redirection
    via HTML content in a MediaWiki page. (CVE-2020-10959)

  - Users can add various Cascading Style Sheets (CSS) classes (which can affect what content is shown or hidden
    in the user interface) to arbitrary DOM nodes via HTML content within a MediaWiki page. This occurs because
    jquery.makeCollapsible allows applying an event handler to any Cascading Style Sheets (CSS) selector. (CVE-2020-10960)");

  script_tag(name:"impact", value:"Successful exploitation would allow the content of the page to affect the MediaWiki interface.");

  script_tag(name:"affected", value:"MediaWiki versions 1.31.0 through 1.31.6, 1.33.0 through 1.33.2 and 1.34.0.");

  script_tag(name:"solution", value:"Update to version 1.31.7, 1.33.3, or 1.34.1 respectively.");

  script_xref(name:"URL", value:"https://phabricator.wikimedia.org/T246602");
  script_xref(name:"URL", value:"https://phabricator.wikimedia.org/T232932");
  script_xref(name:"URL", value:"https://phabricator.wikimedia.org/T240393");
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

if( version_in_range( version: version, test_version: "1.31.0", test_version2: "1.31.6" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.31.7", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "1.33.0", test_version2: "1.33.2" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.33.3", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_is_equal( version: version, test_version: "1.34.0" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.34.1", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
