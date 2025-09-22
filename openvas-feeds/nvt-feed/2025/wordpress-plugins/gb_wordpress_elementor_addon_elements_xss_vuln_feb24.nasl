# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:webtechstreet:elementor_addon_elements";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.128097");
  script_version("2025-05-08T05:40:19+0000");
  script_tag(name:"last_modification", value:"2025-05-08 05:40:19 +0000 (Thu, 08 May 2025)");
  script_tag(name:"creation_date", value:"2025-02-19 10:00:03 +0000 (Wed, 19 Feb 2025)");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-13 19:40:11 +0000 (Tue, 13 Feb 2024)");

  script_cve_id("CVE-2024-0834");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Elementor Addon Elements Plugin < 1.12.12 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/addon-elements-for-elementor-page-builder/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Elementor Addon Elements' is prone to a
  cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The plugin is vulnerable to XSS vulnerability via the link_to
  parameter due to insufficient input sanitization and output escaping.");

  script_tag(name:"affected", value:"WordPress Elementor Addon Elements plugin prior to version
  1.12.12.");

  script_tag(name:"solution", value:"Update to version 1.12.12 or later.");

  script_xref(name:"URL", value:"https://plugins.trac.wordpress.org/browser/addon-elements-for-elementor-page-builder/trunk/modules/price-table/widgets/price-table.php#L784");

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

if (version_is_less(version: version, test_version: "1.12.12")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.12.12", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
