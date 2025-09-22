# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:sygnoos:popup_builder";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.147730");
  script_version("2024-02-08T14:36:53+0000");
  script_tag(name:"last_modification", value:"2024-02-08 14:36:53 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2022-03-01 07:29:45 +0000 (Tue, 01 Mar 2022)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-02-28 20:37:00 +0000 (Mon, 28 Feb 2022)");

  script_cve_id("CVE-2021-25082", "CVE-2022-0228");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Popup Builder Plugin < 4.0.7 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/popup-builder/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Popup Builder' is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2021-25082: Local file inclusion (LFI) to remote code execution (RCE)

  - CVE-2022-0228: Authenticated SQL injection (SQLi)");

  script_tag(name:"affected", value:"WordPress Popup Builder plugin prior to version 4.0.7.");

  script_tag(name:"solution", value:"Update to version 4.0.7 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/0f90f10c-4b0a-46da-ac1f-aa6a03312132");
  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/22facac2-52f4-4e5f-be59-1d2934b260d9");

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

if (version_is_less(version: version, test_version: "4.0.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.0.7", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
