# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:avaya:ip_office";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.144091");
  script_version("2024-09-03T06:26:22+0000");
  script_tag(name:"last_modification", value:"2024-09-03 06:26:22 +0000 (Tue, 03 Sep 2024)");
  script_tag(name:"creation_date", value:"2020-06-09 06:02:13 +0000 (Tue, 09 Jun 2020)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-06-09 19:15:00 +0000 (Tue, 09 Jun 2020)");

  script_cve_id("CVE-2020-7030");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Avaya IP Office 9.x < 10.1.0.8, 11.0 < 11.0.4.3 Information Disclosure Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_avaya_ip_office_http_detect.nasl");
  script_mandatory_keys("avaya/ip_office/detected");

  script_tag(name:"summary", value:"Avaya IP Office is prone to an information disclosure
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A sensitive information disclosure vulnerability was discovered
  in the web interface component of IP Office that may potentially allow a local user to gain
  unauthorized access to the component.");

  script_tag(name:"affected", value:"Avaya IP Office versions 9.x, 10x through 10.1.0.7 and 11.0
  through 11.0.4.2.");

  script_tag(name:"solution", value:"Update to version 10.1.0.8, 11.0.4.3 or later.");

  script_xref(name:"URL", value:"https://downloads.avaya.com/css/P8/documents/101067493");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/157957/Avaya-IP-Office-11-Insecure-Transit-Password-Disclosure.html");

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

if (version_in_range(version: version, test_version: "9.0", test_version2: "10.1.0.7")) {
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
