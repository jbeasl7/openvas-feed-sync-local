# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112628");
  script_version("2024-11-01T05:05:36+0000");
  script_tag(name:"last_modification", value:"2024-11-01 05:05:36 +0000 (Fri, 01 Nov 2024)");
  script_tag(name:"creation_date", value:"2019-08-15 11:09:00 +0000 (Thu, 15 Aug 2019)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-08-14 17:46:00 +0000 (Wed, 14 Aug 2019)");

  script_cve_id("CVE-2019-14794");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Meta Box Plugin < 4.16.2 File Upload Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/meta-box/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Meta Box' is prone to a file upload
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Successful exploitation would allow an authenticated attacker to
  upload arbitrary files in the context of the affected application.");

  script_tag(name:"affected", value:"WordPress Meta Box plugin before version 4.16.2.");

  script_tag(name:"solution", value:"Update to version 4.16.2 or later.");

  script_xref(name:"URL", value:"https://wordpress.org/plugins/meta-box/#developers");
  script_xref(name:"URL", value:"https://www.pluginvulnerabilities.com/2019/01/31/our-proactive-monitoring-caught-an-authenticated-arbitrary-file-upload-vulnerability-being-introduced-in-to-a-wordpress-plugin-with-300000/");

  exit(0);
}

CPE = "cpe:/a:metabox:meta_box";

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "4.16.2" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "4.16.2", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
