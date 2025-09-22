# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mediawiki:mediawiki";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143274");
  script_version("2024-07-16T05:05:43+0000");
  script_tag(name:"last_modification", value:"2024-07-16 05:05:43 +0000 (Tue, 16 Jul 2024)");
  script_tag(name:"creation_date", value:"2019-12-18 08:54:28 +0000 (Wed, 18 Dec 2019)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-12-28 18:15:00 +0000 (Sat, 28 Dec 2019)");

  script_cve_id("CVE-2019-19709");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MediaWiki < 1.31.6 / 1.32.6 / 1.33.2 / 1.34.0 Blacklist Bypass Vulnerability - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_mediawiki_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("mediawiki/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"MediaWiki is prone to a blacklist bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"MediaWiki allows attackers to bypass the Title_blacklist
  protection mechanism by starting with an arbitrary title, establishing a non-resolvable
  redirect for the associated page, and using redirect=1 in the action API when editing
  that page.");

  script_tag(name:"affected", value:"MediaWiki prior to version 1.31.6, 1.32.6, 1.33.2 and
  1.34.0.");

  script_tag(name:"solution", value:"Update MediaWiki to version 1.31.6, 1.32.6, 1.33.2,
  1.34.0 or later.");

  script_xref(name:"URL", value:"https://phabricator.wikimedia.org/T239466");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "1.31.6" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.31.6 / 1.32.6 / 1.33.2 / 1.34.0", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

else if( version =~ "^1\.32" && version_is_less( version: version, test_version: "1.32.6" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.32.6 / 1.33.2 / 1.34.0", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

else if( version =~ "^1\.33" && version_is_less( version: version, test_version: "1.33.2" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.33.2 / 1.34.0", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
