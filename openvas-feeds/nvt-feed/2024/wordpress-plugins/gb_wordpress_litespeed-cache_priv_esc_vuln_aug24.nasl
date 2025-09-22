# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:litespeedtech:litespeed_cache";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.128049");
  script_version("2025-03-18T05:38:50+0000");
  script_tag(name:"last_modification", value:"2025-03-18 05:38:50 +0000 (Tue, 18 Mar 2025)");
  script_tag(name:"creation_date", value:"2024-09-05 10:00:00 +0000 (Thu, 05 Sep 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-03-07 15:20:42 +0000 (Fri, 07 Mar 2025)");

  script_cve_id("CVE-2024-28000");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress LiteSpeed Cache Plugin <= 6.3.0.1 Privilege Escalation Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/litespeed-cache/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'LiteSpeed Cache' is prone to a
  privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The WordPress 'LiteSpeed Cache' plugin is vulnerable to
  the privilege escalation vulnerability due to improper restriction in the role simulation
  functionality.");

  script_tag(name:"impact", value:"Unauthenticated attackers will be able to spoof their user ID to
  administrator ID and read the contents of arbitrary files on the server, which can contain
  sensitive information.");

  script_tag(name:"affected", value:"WordPress LiteSpeed Cache plugin through version 6.3.0.1.");

  script_tag(name:"solution", value:"Update to version 6.4 or later.");

  script_xref(name:"URL", value:"https://patchstack.com/database/vulnerability/litespeed-cache/wordpress-litespeed-cache-plugin-6-3-0-1-unauthenticated-privilege-escalation-vulnerability?_s_id=cve");

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

if( version_is_less_equal( version: version, test_version: "6.3.0.1" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "6.4", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
