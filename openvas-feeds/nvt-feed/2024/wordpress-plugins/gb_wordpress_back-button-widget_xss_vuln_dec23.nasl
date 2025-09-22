# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wpfactory:back_button_widget";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127826");
  script_version("2024-12-20T15:39:18+0000");
  script_tag(name:"last_modification", value:"2024-12-20 15:39:18 +0000 (Fri, 20 Dec 2024)");
  script_tag(name:"creation_date", value:"2024-12-20 08:30:45 +0000 (Fri, 20 Dec 2024)");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-05 04:54:13 +0000 (Fri, 05 Jan 2024)");

  script_cve_id("CVE-2023-51399");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Back Button Widget Plugin < 1.6.4 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/back-button-widget/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Back Button Widget' is prone to a
  cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Insufficient input sanitization and output escaping on user
  supplied attributes.");

  script_tag(name:"impact", value:"Authenticated attackers with contributor-level and above
  permissions are able to inject arbitrary web scripts in pages that will execute whenever a user
  accesses an injected page.");

  script_tag(name:"affected", value:"WordPress Back Button Widget plugin prior to version 1.6.4.");

  script_tag(name:"solution", value:"Update to version 1.6.4 or later.");

  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/id/bcd28bc3-f893-4eb7-946f-34a2e9c7ff27");

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

if( version_is_less( version: version, test_version: "1.6.4" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.6.4", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
