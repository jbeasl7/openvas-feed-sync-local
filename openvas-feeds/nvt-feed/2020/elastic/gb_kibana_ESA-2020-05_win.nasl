# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:elastic:kibana";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.144081");
  script_version("2025-09-03T14:11:39+0000");
  script_tag(name:"last_modification", value:"2025-09-03 14:11:39 +0000 (Wed, 03 Sep 2025)");
  script_tag(name:"creation_date", value:"2020-06-08 06:32:16 +0000 (Mon, 08 Jun 2020)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-14 17:28:00 +0000 (Fri, 14 Aug 2020)");

  script_cve_id("CVE-2020-7012");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Elastic Kibana 6.7.0 < 6.8.9, 7.x <= 7.6.2 Prototype Pollution Vulnerability - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_elastic_kibana_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("elastic/kibana/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Kibana is prone to a prototype pollution vulnerability in the Upgrade
  Assistant.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An authenticated attacker with privileges to write to the Kibana index could
  insert data that would cause Kibana to execute arbitrary code. This could possibly lead to an attacker
  executing code with the permissions of the Kibana process on the host system.");

  script_tag(name:"affected", value:"Kibana versions 6.7.0 - 6.8.8 and 7.0.0 - 7.6.2.");

  script_tag(name:"solution", value:"Update to version 6.8.9, 7.7.0 or later.");

  script_xref(name:"URL", value:"https://www.elastic.co/community/security/");

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

if (version_in_range(version: version, test_version: "6.7.0", test_version2: "6.8.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.8.9", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "7.0", test_version2: "7.6.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.7.0", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
