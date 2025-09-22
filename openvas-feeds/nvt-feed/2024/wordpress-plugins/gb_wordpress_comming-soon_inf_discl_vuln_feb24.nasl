# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:webfactoryltd:minimal_coming_soon";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103077");
  script_version("2024-10-31T05:05:48+0000");
  script_tag(name:"last_modification", value:"2024-10-31 05:05:48 +0000 (Thu, 31 Oct 2024)");
  script_tag(name:"creation_date", value:"2024-05-14 14:00:45 +0000 (Tue, 14 May 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-13 19:43:13 +0000 (Tue, 13 Feb 2024)");

  script_cve_id("CVE-2024-1075");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Minimal Coming Soon - Coming Soon Page Plugin < 2.38 Information Disclosure Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/minimal-coming-soon-maintenance-mode/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Minimal Coming Soon - Coming Soon Page'
  is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The plugin does not validate properly the request path of the
  pages that are in mantainance mode.");

  script_tag(name:"impact", value:"Unauthenticated attackers are able to bypass the plugin and view
  pages that should be hidden.");

  script_tag(name:"affected", value:"WordPress Minimal Coming Soon - Coming Soon Page plugin prior
  to version 2.38.");

  script_tag(name:"solution", value:"Update to version 2.38 or later.");

  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/id/78203b98-15bc-4d8e-9278-c472b518be07?source=cve");

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

if( version_is_less( version: version, test_version: "2.38" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.38", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
