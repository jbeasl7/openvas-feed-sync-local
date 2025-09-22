# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112564");
  script_version("2024-11-01T05:05:36+0000");
  script_tag(name:"last_modification", value:"2024-11-01 05:05:36 +0000 (Fri, 01 Nov 2024)");
  script_tag(name:"creation_date", value:"2019-04-17 13:30:00 +0200 (Wed, 17 Apr 2019)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-08-23 11:15:00 +0000 (Fri, 23 Aug 2019)");

  script_cve_id("CVE-2018-13137");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Events Manager Plugin < 5.9.5 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/events-manager/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Events Manager' is prone to a cross-site
  scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to inject
  malicious content into an affected site.");

  script_tag(name:"affected", value:"WordPress Events Manager plugin before version 5.9.5.");

  script_tag(name:"solution", value:"Update to version 5.9.5 or later.");

  script_xref(name:"URL", value:"https://ansawaf.blogspot.com/2019/04/cve-2018-13137-xss-in-events-manager.html");
  script_xref(name:"URL", value:"https://gist.github.com/ansarisec/12737c207c0851d52865ed60c08891b7");
  script_xref(name:"URL", value:"https://wordpress.org/plugins/events-manager/#developers");

  exit(0);
}

CPE = "cpe:/a:wp-events-plugin:events_manager";

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "5.9.5" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "5.9.5", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
