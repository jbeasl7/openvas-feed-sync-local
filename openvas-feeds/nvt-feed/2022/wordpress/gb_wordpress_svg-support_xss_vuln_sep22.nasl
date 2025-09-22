# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:benbodhi:svg_support";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124192");
  script_version("2025-01-21T05:37:33+0000");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2022-10-11 10:11:08 +0000 (Tue, 11 Oct 2022)");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-09-28 14:24:00 +0000 (Wed, 28 Sep 2022)");

  script_cve_id("CVE-2022-1755");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress SVG Support Plugin < 2.5 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/svg-support/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'SVG Support' is prone to a cross-site
  scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The plugin does not properly handle SVG added via an URL,
  which could allow users with a role as low as author to perform cross-site scripting attacks.");

  script_tag(name:"affected", value:"WordPress SVG Support prior to version 2.5.");

  script_tag(name:"solution", value:"Update to version 2.5 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/62b2548e-6b59-48b8-b1c2-9bd47e634982");

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

if (version_is_less(version: version, test_version: "2.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.5", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
