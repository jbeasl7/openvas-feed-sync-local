# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:aioseo:all_in_one_seo";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124217");
  script_version("2024-11-01T05:05:36+0000");
  script_tag(name:"last_modification", value:"2024-11-01 05:05:36 +0000 (Fri, 01 Nov 2024)");
  script_tag(name:"creation_date", value:"2022-11-17 19:51:57 +0000 (Thu, 17 Nov 2022)");
  script_tag(name:"cvss_base", value:"7.7");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:M/C:C/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-11-09 13:52:00 +0000 (Wed, 09 Nov 2022)");

  script_cve_id("CVE-2022-42494");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress All in One SEO Pack Plugin < 4.2.6 SSRF Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/all-in-one-seo-pack/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'All in One SEO Pack' is prone to a
  server-side request forgery (SSRF) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The web server receives a URL or similar request from an
  upstream component and retrieves the contents of this URL, but it does not sufficiently ensure
  that the request is being sent to the expected destination.");

  script_tag(name:"affected", value:"WordPress All in One SEO Pack plugin prior to version 4.2.6.");

  script_tag(name:"solution", value:"Update to version 4.2.6 or later.");

  script_xref(name:"URL", value:"https://patchstack.com/database/vulnerability/all-in-one-seo-pack-pro/wordpress-all-in-one-seo-pro-plugin-4-2-5-1-server-side-request-forgery-ssrf-vulnerability?_s_id=cve");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: FALSE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "4.2.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.2.6", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
