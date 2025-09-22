# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wpml:wpml";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.135019");
  script_version("2025-08-01T15:45:48+0000");
  script_tag(name:"last_modification", value:"2025-08-01 15:45:48 +0000 (Fri, 01 Aug 2025)");
  script_tag(name:"creation_date", value:"2025-07-28 08:10:51 +0000 (Mon, 28 Jul 2025)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-09-27 13:25:43 +0000 (Fri, 27 Sep 2024)");

  script_cve_id("CVE-2024-6386");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress WPML Multilingual CMS Plugin < 4.6.13 RCE Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/sitepress-multilingual-cms/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'WPML Multilingual CMS' is prone to a
  remote code execution (RCE) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"WordPress WPML Multilingual CMS plugin allows remote attackers
  with contributor level access and above to execute arbitrary code due to missing input validation
  and sanitization of render function in Twig server-side template injection.");

  script_tag(name:"affected", value:"WordPress WPML Multilingual CMS plugin prior to version
  4.6.13.");

  script_tag(name:"solution", value:"Update to version 4.6.13 or later.");

  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/id/f7fc91cc-e529-4362-8269-bf7ee0766e1e");

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

if( version_is_less( version: version, test_version: "4.6.13" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "4.6.13", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
