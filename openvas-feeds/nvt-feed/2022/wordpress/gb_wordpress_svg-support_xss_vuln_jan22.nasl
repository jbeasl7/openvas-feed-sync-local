# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:benbodhi:svg_support";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.147604");
  script_version("2025-01-21T05:37:33+0000");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2022-02-08 03:17:12 +0000 (Tue, 08 Feb 2022)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-02-04 17:30:00 +0000 (Fri, 04 Feb 2022)");

  script_cve_id("CVE-2021-24686");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress SVG Support Plugin < 2.3.20 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/svg-support/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'SVG Support' is prone to a cross-site
  scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The plugin does not escape the 'CSS Class to target' setting
  before outputting it in an attribute, which could allow high privilege users to perform XSS
  attacks even when the unfiltered_html capability is disallowed.");

  script_tag(name:"affected", value:"WordPress SVG Support version 2.3.19 and prior.");

  script_tag(name:"solution", value:"Update to version 2.3.20 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/38018695-901d-48d9-b39a-7c00df7f0a4b");

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

if (version_is_less(version: version, test_version: "2.3.20")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.3.20", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
