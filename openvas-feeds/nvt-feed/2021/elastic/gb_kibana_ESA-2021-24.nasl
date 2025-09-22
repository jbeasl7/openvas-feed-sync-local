# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:elastic:kibana";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.117776");
  script_version("2025-09-03T14:11:39+0000");
  script_tag(name:"last_modification", value:"2025-09-03 14:11:39 +0000 (Wed, 03 Sep 2025)");
  script_tag(name:"creation_date", value:"2021-09-27 11:31:59 +0000 (Mon, 27 Sep 2021)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-08-24 13:54:00 +0000 (Tue, 24 Aug 2021)");

  script_cve_id("CVE-2021-22940", "CVE-2021-3672", "CVE-2021-22931", "CVE-2021-22939");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Elastic Kibana Node.js Security Vulnerabilities (ESA-2021-24)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_elastic_kibana_http_detect.nasl");
  script_mandatory_keys("elastic/kibana/detected");

  script_tag(name:"summary", value:"Elastic Kibana is prone to multiple vulnerabilities in Node.js.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Node.js version 14.17.3 is affected by several security
  vulnerabilities: CVE-2021-22940, CVE-2021-3672, CVE-2021-22931, and CVE-2021-22939. We do not
  believe an attacker can exploit these against Kibana, but we are upgrading Node.js out of an
  abundance of caution. Kibana 7.14.1 upgrades Node.js to version 14.17.5 to resolve these issues.");

  script_tag(name:"affected", value:"Elastic Kibana version 7.14.0 and prior.");

  script_tag(name:"solution", value:"Update to version 7.14.1 or later.");

  script_xref(name:"URL", value:"https://discuss.elastic.co/t/elastic-stack-7-14-1-security-update/283077");

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

if (version_is_less(version: version, test_version: "7.14.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.14.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
