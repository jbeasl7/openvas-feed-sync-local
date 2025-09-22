# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:elementor:website_builder";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126057");
  script_version("2025-01-21T05:37:33+0000");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2022-07-01 11:23:30 +0000 (Fri, 01 Jul 2022)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-06-27 16:18:00 +0000 (Mon, 27 Jun 2022)");

  script_cve_id("CVE-2022-29455");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Elementor Page Builder Plugin <= 3.5.5 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/elementor/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Elementor Page Builder' is prone
  to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"An attacker could do the following: account takeovers,
  executing javascript on victim's behalf, SOAP bypass, CORS bypass, Defacement.");

  script_tag(name:"affected", value:"WordPress Elementor Page Builder plugin version 3.5.5 and prior.");

  script_tag(name:"solution", value:"Update to version 3.5.6 or later.");

  script_xref(name:"URL", value:"https://patchstack.com/database/vulnerability/elementor/wordpress-elementor-plugin-3-5-5-unauthenticated-dom-based-reflected-cross-site-scripting-xss-vulnerability");
  script_xref(name:"URL", value:"https://rotem-bar.com/hacking-65-million-websites-greater-cve-2022-29455-elementor");
  script_xref(name:"URL", value:"https://www.wordfence.com/blog/2022/04/elementor-critical-remote-code-execution-vulnerability/");

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

if (version_is_less_equal(version: version, test_version: "3.5.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.5.6", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
