# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:expresstech:quiz_and_survey_master";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127946");
  script_version("2025-08-22T15:40:55+0000");
  script_tag(name:"last_modification", value:"2025-08-22 15:40:55 +0000 (Fri, 22 Aug 2025)");
  script_tag(name:"creation_date", value:"2025-08-21 09:11:08 +0000 (Thu, 21 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2025-6790");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Quiz And Survey Master Plugin < 10.2.3 CSRF Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/quiz-master-next/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Quiz And Survey Master' is prone to a
  cross-site request forgery (CSRF) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The plugin does not have CSRF check in place when updating its
  settings, which could allow attackers to make a logged in admin change them via a CSRF attack.");

  script_tag(name:"affected", value:"WordPress Quiz And Survey Master plugin prior to version
  10.2.3.");

  script_tag(name:"solution", value:"Update to version 10.2.3 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/af337f9f-c955-49eb-9675-2f85da96fcfe/");

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

if( version_is_less( version: version, test_version: "10.2.3" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "10.2.3", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
