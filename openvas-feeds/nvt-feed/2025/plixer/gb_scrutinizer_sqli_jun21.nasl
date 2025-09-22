# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:plixer:scrutinizer";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.125150");
  script_version("2025-02-27T08:17:42+0000");
  script_tag(name:"last_modification", value:"2025-02-27 08:17:42 +0000 (Thu, 27 Feb 2025)");
  script_tag(name:"creation_date", value:"2025-02-25 13:51:43 +0000 (Tue, 25 Feb 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-06 13:26:25 +0000 (Tue, 06 Jul 2021)");

  script_cve_id("CVE-2021-28993");

  script_tag(name:"qod_type", value:"remote_app");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Plixer / Dell SonicWALL Scrutinizer 19.0.2 SQLi Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_plixer_dell_scrutinizer_http_detect.nasl");
  script_mandatory_keys("plixer_dell/scrutinizer/http/detected");

  script_tag(name:"summary", value:"Plixer / Dell SonicWALL Scrutinizer is prone to an SQL injection
  (SQLi) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Plixer Scrutinizer is vulnerable to SQL Injection, which could
  allow remote attackers to obtain sensitive information.");

  script_tag(name:"affected", value:"Plixer / Dell SonicWALL Scrutinizer version 19.0.2.");

  script_tag(name:"solution", value:"Update to version 19.1.0 or later.");

  script_xref(name:"URL", value:"https://docs.plixer.com/projects/scrutinizer/en/19.1.0/system/changelog.html");

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

if (version_is_equal(version: version, test_version: "19.0.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "19.1.0", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
