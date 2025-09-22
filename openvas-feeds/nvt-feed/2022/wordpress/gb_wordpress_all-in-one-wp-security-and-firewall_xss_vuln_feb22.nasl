# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124063");
  script_version("2024-11-01T05:05:36+0000");
  script_tag(name:"last_modification", value:"2024-11-01 05:05:36 +0000 (Fri, 01 Nov 2024)");
  script_tag(name:"creation_date", value:"2022-05-04 14:15:43 +0000 (Wed, 04 May 2022)");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-05-10 13:14:00 +0000 (Tue, 10 May 2022)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2021-25102");

  script_name("WordPress All In One WP Security & Firewall Plugin < 4.4.11 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/all-in-one-wp-security-and-firewall/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'All In One WP Security & Firewall'
  is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The All In One WP Security & Firewall WordPress plugin does not validate, sanitise
  and escape the redirect_to parameter before using it to redirect user, either via a Location header,
  or meta url attribute, when the Rename Login Page is active, which could lead to an Arbitrary
  Redirect as well as Cross-Site Scripting issue.");

  script_tag(name:"affected", value:"WordPress All In One WP Security & Firewall plugin prior to 4.4.11 version.");

  script_tag(name:"solution", value:"Update to version 4.4.11 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/9b8a00a6-622b-4309-bbbf-fe2c7fc9f8b6");

  exit(0);
}

CPE = "cpe:/a:tipsandtricks-hq:all_in_one_wp_security_%26_firewall";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "4.4.11" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "4.4.11", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
