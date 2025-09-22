# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mediaburst:gravity_forms";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124883");
  script_version("2025-08-15T05:40:49+0000");
  script_tag(name:"last_modification", value:"2025-08-15 05:40:49 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"creation_date", value:"2025-08-11 08:10:51 +0000 (Mon, 11 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Gravity Forms Plugin < 1.8.20 Arbitrary File Upload Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/gravityforms/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Gravity Forms' is prone to an arbitrary
  file upload vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Plugin is vulnerable to arbitrary file upload.");

  script_tag(name:"affected", value:"WordPress Gravity Forms plugin prior to version 1.8.20.");

  script_tag(name:"solution", value:"Update to version 1.8.20 or later.");

  script_xref(name:"URL", value:"https://blog.sucuri.net/2015/02/malware-cleanup-to-arbitrary-file-upload-in-gravity-forms.html");

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

if( version_is_less( version: version, test_version: "1.8.20" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.8.20", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
