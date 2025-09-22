# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:nextendweb:smart_slider_3";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126693");
  script_version("2025-01-13T08:32:03+0000");
  script_tag(name:"last_modification", value:"2025-01-13 08:32:03 +0000 (Mon, 13 Jan 2025)");
  script_tag(name:"creation_date", value:"2024-04-22 06:15:24 +0000 (Mon, 22 Apr 2024)");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-04-13 02:15:06 +0000 (Sat, 13 Apr 2024)");

  script_cve_id("CVE-2024-3027");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress The Smart Slider 3 Plugin < 3.5.1.23 Improper Authorization Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/smart-slider-3/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'The Smart Slider 3' is prone to an
  improper authorization vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The plugin allows to unauthorized modification of data due to a
  missing capability check on the upload function.");

  script_tag(name:"affected", value:"WordPress Smart Slider 3 plugin prior to version 3.5.1.23.");

  script_tag(name:"solution", value:"Update to version 3.5.1.23 or later.");

  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/smart-slider-3/smart-slider-3-35122-missing-authorization-to-limited-file-upload");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "3.5.1.23")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.5.1.23", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
