# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:aioseo:all_in_one_seo";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127182");
  script_version("2024-11-01T05:05:36+0000");
  script_tag(name:"last_modification", value:"2024-11-01 05:05:36 +0000 (Fri, 01 Nov 2024)");
  script_tag(name:"creation_date", value:"2022-09-12 09:51:57 +0000 (Mon, 12 Sep 2022)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-09-10 03:33:00 +0000 (Sat, 10 Sep 2022)");

  script_cve_id("CVE-2022-38093");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress All in One SEO Pack Plugin < 4.2.4 CSRF Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/all-in-one-seo-pack/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'All in One SEO Pack' is prone to a
  cross-site request forgery (CSRF) vulnerability.");

  script_tag(name:"insight", value:"The plugin does not, or can not, sufficiently verify whether a
  well-formed, valid, consistent request was intentionally provided by the user who submitted the
  request.");

  script_tag(name:"affected", value:"WordPress All in One SEO Pack plugin prior to version 4.2.4.");

  script_tag(name:"solution", value:"Update to version 4.2.4 or later.");

  script_xref(name:"URL", value:"https://patchstack.com/database/vulnerability/all-in-one-seo-pack/wordpress-all-in-one-seo-plugin-4-2-3-1-multiple-cross-site-request-forgery-csrf-vulnerabilities/");

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

if (version_is_less(version: version, test_version: "4.2.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.2.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
