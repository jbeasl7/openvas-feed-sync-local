# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113486");
  script_version("2024-11-01T05:05:36+0000");
  script_tag(name:"last_modification", value:"2024-11-01 05:05:36 +0000 (Fri, 01 Nov 2024)");
  script_tag(name:"creation_date", value:"2019-09-02 11:59:04 +0000 (Mon, 02 Sep 2019)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-08-21 15:07:00 +0000 (Wed, 21 Aug 2019)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2018-20972", "CVE-2018-20973");

  script_name("WordPress Companion Auto Update Plugin < 3.2.1 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/companion-auto-update/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Companion Auto Update' is prone to
  multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The plugin is affected by both a cross-site request forgery
  (CSRF) vulnerability and a local file inclusion (LFI) vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to perform
  actions in the context of another user or execute code on the target machine.");

  script_tag(name:"affected", value:"WordPress Companion Auto Update plugin through version 3.2.0.");

  script_tag(name:"solution", value:"Update to version 3.2.1 or later.");

  script_xref(name:"URL", value:"https://wordpress.org/plugins/companion-auto-update/#developers");

  exit(0);
}

CPE = "cpe:/a:codeermeneer:companion_auto_update";

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "3.2.1" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.2.1", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
