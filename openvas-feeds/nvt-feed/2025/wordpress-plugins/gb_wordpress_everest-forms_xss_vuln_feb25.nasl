# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.128103");
  script_version("2025-02-27T08:17:42+0000");
  script_tag(name:"last_modification", value:"2025-02-27 08:17:42 +0000 (Thu, 27 Feb 2025)");
  script_tag(name:"creation_date", value:"2025-02-25 09:16:00 +0000 (Tue, 25 Feb 2025)");
  script_tag(name:"cvss_base", value:"3.2");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:M/C:P/I:P/A:N");

  script_cve_id("CVE-2024-13125");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Everest Forms Plugin < 3.0.8.1 - Authenticated (Admin+) XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/everest-forms/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Everest Forms' is prone to a
  cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The plugin is vulnerable to XSS attacks via admin settings
  due to insufficient input sanitization and output escaping.");

  script_tag(name:"affected", value:"WordPress Everest Forms plugin before version 3.0.8.1.");

  script_tag(name:"solution", value:"Update to version 3.0.8.1 or later.");

  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/everest-forms/everest-forms-contact-forms-quiz-survey-newsletter-payment-form-builder-for-wordpress-308-authenticated-admin-stored-cross-site-scripting");

  exit(0);
}

CPE = "cpe:/a:wpeverest:everest_forms";

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "3.0.8.1" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.0.8.1", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
