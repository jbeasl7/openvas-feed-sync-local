# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wpdeveloper:essential_addons_for_elementor";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.128037");
  script_version("2025-01-13T08:32:03+0000");
  script_tag(name:"last_modification", value:"2025-01-13 08:32:03 +0000 (Mon, 13 Jan 2025)");
  script_tag(name:"creation_date", value:"2024-08-01 10:00:00 +0000 (Thu, 01 Aug 2024)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-03-30 12:15:07 +0000 (Sat, 30 Mar 2024)");

  script_cve_id("CVE-2024-3018", "CVE-2024-2974");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Essential Addons for Elementor Plugin < 5.9.14 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/essential-addons-for-elementor-lite/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Essential Addons for Elementor' is prone
  to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2024-3018: PHP Object Injection vulnerability exists via deserialization of untrusted
  input from the 'error_resetpassword' attribute of the 'Login Register Form' widget.

  - CVE-2024-2974: Sensitive Information Exposure vulnerability exists via the load_more function.");

  script_tag(name:"affected", value:"WordPress Essential Addons for Elementor plugin through
  version 5.9.13");

  script_tag(name:"solution", value:"Update to version 5.9.14 or later.");

  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/id/342049e5-834e-4867-8174-01ca7bb0caa2?source=cve");
  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/id/78f96d7f-aeca-4959-9573-0fb6402de007?source=cve");

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

if (version_is_less(version: version, test_version: "5.9.14")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.9.14", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit( 99 );