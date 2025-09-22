# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:givewp:givewp";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127117");
  script_version("2025-07-18T15:43:33+0000");
  script_tag(name:"last_modification", value:"2025-07-18 15:43:33 +0000 (Fri, 18 Jul 2025)");
  script_tag(name:"creation_date", value:"2022-08-02 09:16:07 +0000 (Tue, 02 Aug 2022)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-05 21:46:00 +0000 (Fri, 05 Aug 2022)");

  script_cve_id("CVE-2022-2215", "CVE-2022-2260");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress GiveWP Plugin < 2.21.3 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/give/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'GiveWP' is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2022-2215: The plugin does not properly escape the currency settings which could lead to
  cross-site scripting (XSS).

  - CVE-2022-2260: The plugin does not validate the exporting parameters which allow attackers to
  make a logged in admin DoS the web server via a cross-site request forgery (CSRF) attack.");

  script_tag(name:"affected", value:"WordPress GiveWP plugin prior to version 2.21.3.");

  script_tag(name:"solution", value:"Update to version 2.21.3 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/831b3afa-8fa3-4cb7-8374-36d0c368292f");
  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/daa9b6c1-1ee1-434c-9f88-fd273b7e20bb");
  script_xref(name:"URL", value:"https://wordpress.org/plugins/give/#developers");

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

if (version_is_less(version: version, test_version: "2.21.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.21.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
