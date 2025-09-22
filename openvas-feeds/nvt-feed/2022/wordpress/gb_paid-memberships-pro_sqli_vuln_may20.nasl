# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:paidmembershipspro:paid_memberships_pro";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127203");
  script_version("2023-11-03T05:05:46+0000");
  script_tag(name:"last_modification", value:"2023-11-03 05:05:46 +0000 (Fri, 03 Nov 2023)");
  script_tag(name:"creation_date", value:"2022-09-22 09:00:43 +0000 (Thu, 22 Sep 2022)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-03-23 16:26:00 +0000 (Tue, 23 Mar 2021)");

  script_cve_id("CVE-2020-5579");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Paid Memberships Pro Plugin < 2.3.3 SQLi Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/paid-memberships-pro/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Paid Memberships Pro' is prone to a
  SQL injection (SQLi) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A user is able to execute SQLi vulnerability while logged in as
  an administrator and adding new orders in the dashboard.");

  script_tag(name:"affected", value:"WordPress Paid Memberships Pro prior to version 2.3.3.");

  script_tag(name:"solution", value:"Update to version 2.3.3 or later.");

  script_xref(name:"URL", value:"https://www.paidmembershipspro.com/pmpro-update-2-3-3-security-release/");

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

if (version_is_less(version: version, test_version: "2.3.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.3.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
