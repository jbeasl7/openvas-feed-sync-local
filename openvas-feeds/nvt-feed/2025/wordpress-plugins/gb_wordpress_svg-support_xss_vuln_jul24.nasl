# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:benbodhi:svg_support";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124708");
  script_version("2025-04-09T05:39:51+0000");
  script_tag(name:"last_modification", value:"2025-04-09 05:39:51 +0000 (Wed, 09 Apr 2025)");
  script_tag(name:"creation_date", value:"2025-02-05 08:11:08 +0000 (Wed, 05 Feb 2025)");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-18 03:15:02 +0000 (Thu, 18 Jul 2024)");

  script_cve_id("CVE-2023-6708");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress SVG Support Plugin < 2.5.8 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/svg-support/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'SVG Support' is prone to a cross-site
  scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"An authenticated attacker, with author-level access and
  above, is able to inject arbitrary web scripts in pages that will execute whenever a user
  accesses an injected page.");

  script_tag(name:"affected", value:"WordPress SVG Support prior to version 2.5.8.");

  script_tag(name:"solution", value:"Update to version 2.5.8 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/e168ed43-e6a6-4105-beb1-0c5265767d6d/");

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

if (version_is_less(version: version, test_version: "2.5.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.5.8", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
