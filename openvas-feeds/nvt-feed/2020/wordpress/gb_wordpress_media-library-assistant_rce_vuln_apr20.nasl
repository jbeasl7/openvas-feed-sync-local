# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113676");
  script_version("2024-11-01T05:05:36+0000");
  script_tag(name:"last_modification", value:"2024-11-01 05:05:36 +0000 (Fri, 01 Nov 2024)");
  script_tag(name:"creation_date", value:"2020-04-27 08:28:47 +0000 (Mon, 27 Apr 2020)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-04-22 15:52:00 +0000 (Wed, 22 Apr 2020)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2020-11928");

  script_name("WordPress Media Library Assistant Plugin < 2.82 RCE Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/media-library-assistant/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Media Library Assistant' is prone to
  a remote code execution (RCE) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability can be exploited by an admin via
  the tax_query, meta_query or date_query parameter in mla_gallery.");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to
  execute arbitrary code on the target machine.");

  script_tag(name:"affected", value:"WordPress Media Library Assistant plugin through version 2.81.");

  script_tag(name:"solution", value:"Update to version 2.82 or later.");

  script_xref(name:"URL", value:"https://wordpress.org/plugins/media-library-assistant/#developers");

  exit(0);
}

CPE = "cpe:/a:media_library_assistant_project:media_library_assistant";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "2.82" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.82", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
