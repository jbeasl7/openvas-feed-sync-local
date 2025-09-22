# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wpmudev:smush_image_compression_and_optimization";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112073");
  script_version("2024-11-01T05:05:36+0000");
  script_tag(name:"last_modification", value:"2024-11-01 05:05:36 +0000 (Fri, 01 Nov 2024)");
  script_tag(name:"creation_date", value:"2017-10-09 09:55:51 +0200 (Mon, 09 Oct 2017)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-10-13 17:57:00 +0000 (Fri, 13 Oct 2017)");

  script_cve_id("CVE-2017-15079");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Smush Image Compression and Optimization Plugin < 2.7.6 Directory Traversal Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/wp-smushit/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Smush Image Compression and Optimization'
  is prone to a directory traversal vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"WordPress Smush Image Compression and Optimization plugin prior
  to version 2.7.6.");

  script_tag(name:"solution", value:"Update to version 2.7.6 or later.");

  script_xref(name:"URL", value:"https://wordpress.org/plugins/wp-smushit/#developers");
  script_xref(name:"URL", value:"https://wordpress.org/support/topic/file-transversal-bug/");

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

if( version_is_less( version: version, test_version: "2.7.6" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.7.6", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
