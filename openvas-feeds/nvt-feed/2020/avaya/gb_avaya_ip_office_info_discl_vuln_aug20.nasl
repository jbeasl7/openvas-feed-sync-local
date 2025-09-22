# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:avaya:ip_office";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.144380");
  script_version("2024-09-03T06:26:22+0000");
  script_tag(name:"last_modification", value:"2024-09-03 06:26:22 +0000 (Tue, 03 Sep 2024)");
  script_tag(name:"creation_date", value:"2020-08-10 08:40:53 +0000 (Mon, 10 Aug 2020)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-11 19:26:00 +0000 (Tue, 11 Aug 2020)");

  script_cve_id("CVE-2019-7005");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Avaya IP Office 10.x < 10.1.0.8, 11.0 < 11.0.4.3 Information Disclosure Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_avaya_ip_office_http_detect.nasl");
  script_mandatory_keys("avaya/ip_office/detected");

  script_tag(name:"summary", value:"Avaya IP Office is prone to an information disclosure
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A vulnerability was discovered in the web interface component
  of IP Office that could potentially allow an unauthenticated user to gain access to sensitive
  information.");

  script_tag(name:"affected", value:"Avaya IP Office versions 10.0 through 10.1.0.7 and 11.0
  through 11.0.4.2.");

  script_tag(name:"solution", value:"Update to version 10.1.0.8, 11.0.4.3 or later.");

  script_xref(name:"URL", value:"https://downloads.avaya.com/css/P8/documents/101070158");

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

if (version_in_range(version: version, test_version: "10.0", test_version2: "10.1.0.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.1.0.8", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "11.0", test_version2: "11.0.4.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "11.0.4.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
