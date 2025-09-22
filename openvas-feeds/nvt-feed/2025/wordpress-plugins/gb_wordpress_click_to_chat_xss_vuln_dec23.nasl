# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:quadlayers:wp_social_chat";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.128093");
  script_version("2025-05-08T05:40:19+0000");
  script_tag(name:"last_modification", value:"2025-05-08 05:40:19 +0000 (Thu, 08 May 2025)");
  script_tag(name:"creation_date", value:"2025-02-17 07:30:48 +0000 (Mon, 17 Feb 2025)");
  script_tag(name:"cvss_base", value:"4.7");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:M/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-10-10 12:46:36 +0000 (Thu, 10 Oct 2024)");

  script_cve_id("CVE-2023-51370");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Click To Chat App Plugin < 3.4.5 - Authenticated (Administrator+) XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/wp-whatsapp-chat/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Click To Chat App' is prone
  to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The plugin is vulnerable to stored XSS via admin settings due to
  insufficient input sanitization and output escaping.");

  script_tag(name:"impact", value:"Authenticated attackers with administrator-level permissions can
  inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.");

  script_tag(name:"affected", value:"WordPress Click To Chat App plugin prior to version 3.4.5.");

  script_tag(name:"solution", value:"Update to version 3.4.5 or later.");

  script_xref(name:"URL", value:"https://patchstack.com/database/wordpress/plugin/wp-whatsapp/vulnerability/wordpress-wp-chat-app-plugin-3-4-4-cross-site-scripting-xss-vulnerability?_s_id=cve");
  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/wp-whatsapp/wp-chat-app-344-authenticated-administrator-stored-cross-site-scripting");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "3.4.5" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.4.5", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
