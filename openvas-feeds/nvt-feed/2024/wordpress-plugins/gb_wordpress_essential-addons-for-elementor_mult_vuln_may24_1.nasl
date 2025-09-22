# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wpdeveloper:essential_addons_for_elementor";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.128038");
  script_version("2024-08-06T05:05:45+0000");
  script_tag(name:"last_modification", value:"2024-08-06 05:05:45 +0000 (Tue, 06 Aug 2024)");
  script_tag(name:"creation_date", value:"2024-08-01 10:00:00 +0000 (Thu, 01 Aug 2024)");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-05-02 17:15:33 +0000 (Thu, 02 May 2024)");

  script_cve_id("CVE-2024-3728", "CVE-2024-4003");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Essential Addons for Elementor Plugin < 5.9.16 Multiple XSS Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/essential-addons-for-elementor-lite/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Essential Addons for Elementor' is prone
  to multiple cross-site scripting (XSS) vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2024-3728: Insufficient input sanitization and output escaping on user supplied attributes
  allows Stored Cross-site Scripting vulnerability via the plugin's Filterable Gallery & Interactive
  Circle widgets.

  - CVE-2024-4003: Insufficient input sanitization and output escaping allows Stored Cross-site
  Scripting vulnerability via the eael_team_members_image_rounded parameter in the Team Members
  widget");

  script_tag(name:"affected", value:"WordPress Essential Addons for Elementor plugin through
  version 5.9.15.");

  script_tag(name:"solution", value:"Update to version 5.9.16 or later.");

  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/id/284ea577-ff67-4681-995b-f7bb5ef0ff3e?source=cve");
  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/id/1cf3190c-e247-4bcc-99e0-2ab2d2fa0590?source=cve");

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

if (version_is_less(version: version, test_version: "5.9.16")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.9.16", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit( 99 );