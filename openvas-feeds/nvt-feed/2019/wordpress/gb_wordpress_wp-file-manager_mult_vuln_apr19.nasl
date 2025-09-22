# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112566");
  script_version("2025-01-21T05:37:33+0000");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2019-04-17 15:25:00 +0200 (Wed, 17 Apr 2019)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-09-03 05:15:00 +0000 (Tue, 03 Sep 2019)");

  script_cve_id("CVE-2018-16966", "CVE-2018-16967");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress File Manager Plugin <= 3.0 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/wp-file-manager/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'File Manager' is prone to multiple
  vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to inject
  malicious content into an affected site or to force an end user to execute unwanted actions on the
  vulnerable web application.");

  script_tag(name:"affected", value:"WordPress File Manager plugin through version 3.0.");

  script_tag(name:"solution", value:"Update to version 3.1 or later.");

  script_xref(name:"URL", value:"https://ansawaf.blogspot.com/2019/04/file-manager-plugin-wordpress-plugin.html");
  script_xref(name:"URL", value:"https://wordpress.org/plugins/wp-file-manager/#developers");

  exit(0);
}

CPE = "cpe:/a:webdesi9:file_manager";

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "3.1" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.1", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
