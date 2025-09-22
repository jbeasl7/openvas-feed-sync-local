# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:flippercode:wp_google_map";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.145605");
  script_version("2025-01-21T05:37:33+0000");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2021-03-22 08:27:14 +0000 (Mon, 22 Mar 2021)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-03-24 17:11:00 +0000 (Wed, 24 Mar 2021)");

  script_cve_id("CVE-2021-24130");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress WP Google Map Plugin < 4.1.5 SQLi Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/wp-google-map-plugin/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'WP Google Map' is prone to an
  SQL injection (SQLi) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Unvalidated input in the WP Google Map WordPress plugin in the
  Manage Locations page within the plugin settings was vulnerable to SQLi through a high privileged
  user (admin+).");

  script_tag(name:"affected", value:"WordPress WP Google Map plugin through version 4.1.4.");

  script_tag(name:"solution", value:"Update to version 4.1.5 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/46af9a4d-67ac-4e08-a753-a2a44245f4f8");
  script_xref(name:"URL", value:"https://wordpress.org/plugins/wp-google-map-plugin/#developers");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "4.1.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.1.5", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
