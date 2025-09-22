# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:elastic:kibana";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.144340");
  script_version("2025-09-03T14:11:39+0000");
  script_tag(name:"last_modification", value:"2025-09-03 14:11:39 +0000 (Wed, 03 Sep 2025)");
  script_tag(name:"creation_date", value:"2020-08-03 07:24:12 +0000 (Mon, 03 Aug 2020)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:H/I:H/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-25 15:38:00 +0000 (Tue, 25 Aug 2020)");

  script_cve_id("CVE-2020-7016", "CVE-2020-7017");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Elastic Kibana < 6.8.11, 7.x < 7.8.1 Multiple Vulnerabilities - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_elastic_kibana_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("elastic/kibana/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Kibana is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - Regular expression denial of service flaw (CVE-2020-7016)

  - Cross-site scripting (CVE-2020-7017)");

  script_tag(name:"affected", value:"Kibana prior to version 6.8.11 and 7.8.1.");

  script_tag(name:"solution", value:"Update to version 6.8.11, 7.8.1 or later.");

  script_xref(name:"URL", value:"https://discuss.elastic.co/t/elastic-stack-6-8-11-and-7-8-1-security-update/242786");

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

if (version_is_less(version: version, test_version: "6.8.11")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.8.11", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "7.0", test_version2: "7.8.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.8.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
