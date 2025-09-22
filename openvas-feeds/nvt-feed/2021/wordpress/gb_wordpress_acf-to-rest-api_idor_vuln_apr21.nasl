# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113814");
  script_version("2024-11-01T05:05:36+0000");
  script_tag(name:"last_modification", value:"2024-11-01 05:05:36 +0000 (Fri, 01 Nov 2024)");
  script_tag(name:"creation_date", value:"2021-04-13 09:09:02 +0000 (Tue, 13 Apr 2021)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-07-01 21:17:00 +0000 (Wed, 01 Jul 2020)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2020-13700");

  script_name("WordPress ACF to REST API Plugin <= 3.1.0 IDOR Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/acf-to-rest-api/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'ACF to REST API' is prone to an insecure direct object reference (IDOR) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability is exploitable via
  a request to wp-json/acf/v3/options/.");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker
  to read sensitive information.");

  script_tag(name:"affected", value:"WordPress ACF to REST API plugin through version 3.1.0.");

  script_tag(name:"solution", value:"Update to version 3.2.0 or later.");

  script_xref(name:"URL", value:"https://gist.github.com/mariuszpoplwski/4fbaab7f271bea99c733e3f2a4bafbb5");

  exit(0);
}

CPE = "cpe:/a:acf_to_rest_api_project:acf_to_rest_api";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "3.2.0" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.2.0", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
