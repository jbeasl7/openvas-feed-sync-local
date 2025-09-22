# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mediaburst:gravity_forms";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124879");
  script_version("2025-08-15T05:40:49+0000");
  script_tag(name:"last_modification", value:"2025-08-15 05:40:49 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"creation_date", value:"2025-08-11 08:10:51 +0000 (Mon, 11 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-06-03 17:58:24 +0000 (Wed, 03 Jun 2020)");

  script_cve_id("CVE-2020-13764");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Gravity Forms Plugin < 2.4.9 Information Disclosure Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/gravityforms/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Gravity Forms' is prone to an information
  disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The gravityforms WordPress plugin was affected by a Hashed
  Password Leakage security vulnerability.");

  script_tag(name:"affected", value:"WordPress Gravity Forms plugin prior to version 2.4.9.");

  script_tag(name:"solution", value:"Update to version 2.4.9 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/09a9ced9-ff06-42e3-964f-c51230a95e32/");

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

if( version_is_less( version: version, test_version: "2.4.9" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.4.9", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
