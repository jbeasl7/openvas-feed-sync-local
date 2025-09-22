# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:properfraction:profilepress";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.146798");
  script_version("2025-01-21T05:37:33+0000");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2021-09-28 15:10:51 +0000 (Tue, 28 Sep 2021)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-08-17 16:00:00 +0000 (Tue, 17 Aug 2021)");

  script_cve_id("CVE-2021-24522");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress ProfilePress Plugin < 3.1.11 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/wp-user-avatar/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'ProfilePress (Formerly WP User Avatar)' is
  prone to an unauthenticated cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"WordPress ProfilePress plugin prior to version 3.1.11.");

  script_tag(name:"solution", value:"Update to version 3.1.11 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/25b51add-197c-4aff-b1a8-b92fb11d8697");

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

if (version_is_less(version: version, test_version: "3.1.11")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.1.11", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
