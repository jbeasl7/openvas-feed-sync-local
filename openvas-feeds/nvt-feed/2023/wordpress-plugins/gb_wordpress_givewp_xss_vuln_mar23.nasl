# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:givewp:givewp";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127424");
  script_version("2023-11-17T16:10:13+0000");
  script_tag(name:"last_modification", value:"2023-11-17 16:10:13 +0000 (Fri, 17 Nov 2023)");
  script_tag(name:"creation_date", value:"2023-05-09 07:44:07 +0000 (Tue, 09 May 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-15 18:40:00 +0000 (Wed, 15 Nov 2023)");

  script_cve_id("CVE-2023-22719", "CVE-2023-23668", "CVE-2023-25450");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress GiveWP Plugin < 2.25.2 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/give/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'GiveWP' is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2023-22719: Attackers are able to embed untrusted input into exported CSV files via the
  'print_csv_rows' function.

  - CVE-2023-23668: The plugin does not validate and escape some of its shortcode
  attributes before outputting them back in a page/post where the shortcode is embed.

  - CVE-2023-25450: Attackers are able to flush the GiveWP cache via forged request granted due to
  missing or incorrect nonce validation on the 'give_cache_flush' AJAX function.");

  script_tag(name:"affected", value:"WordPress GiveWP plugin prior to version 2.25.2.");

  script_tag(name:"solution", value:"Update to version 2.25.2 or later.");

  script_xref(name:"URL", value:"https://patchstack.com/database/vulnerability/give/wordpress-givewp-plugin-2-25-1-csv-injection-vulnerability");
  script_xref(name:"URL", value:"https://patchstack.com/database/vulnerability/give/wordpress-givewp-plugin-2-25-1-contributor-cross-site-scripting-xss-vulnerability");
  script_xref(name:"URL", value:"https://patchstack.com/database/vulnerability/give/wordpress-givewp-plugin-2-25-1-cross-site-request-forgery-csrf-via-give-cache-flush-vulnerability");

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

if( version_is_less( version: version, test_version: "2.25.2" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.25.2", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
