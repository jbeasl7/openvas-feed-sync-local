# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:nagios:nagios";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.144107");
  script_version("2025-09-11T05:38:37+0000");
  script_tag(name:"last_modification", value:"2025-09-11 05:38:37 +0000 (Thu, 11 Sep 2025)");
  script_tag(name:"creation_date", value:"2020-06-15 07:00:06 +0000 (Mon, 15 Jun 2020)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-28 12:58:00 +0000 (Mon, 28 Sep 2020)");

  script_cve_id("CVE-2020-1408", "CVE-2020-13977");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Nagios Core < 4.4.6 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_nagios_http_detect.nasl");
  script_mandatory_keys("nagios/detected");

  script_tag(name:"summary", value:"Nagios Core is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Nagios Core is prone to multiple vulnerabilities:

  - Authenticated vulnerabilities in histogram.js, map.js, trends.js (CVE-2020-1408)

  - URL injection vulnerability (CVE-2020-13977)");

  script_tag(name:"affected", value:"Nagios Core version 4.4.5 and prior.");

  script_tag(name:"solution", value:"Update to version 4.4.6 or later.");

  script_xref(name:"URL", value:"https://anhtai.me/nagios-core-4-4-5-url-injection/");
  script_xref(name:"URL", value:"https://www.nagios.org/projects/nagios-core/history/4x/");

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

if (version_is_less(version: version, test_version: "4.4.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.4.6", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
