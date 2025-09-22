# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:elastic:kibana";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126336");
  script_version("2025-09-03T14:11:39+0000");
  script_tag(name:"last_modification", value:"2025-09-03 14:11:39 +0000 (Wed, 03 Sep 2025)");
  script_tag(name:"creation_date", value:"2023-02-06 15:00:34 +0000 (Mon, 06 Feb 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-07-29 14:18:00 +0000 (Fri, 29 Jul 2022)");

  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2022-1364");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Elastic Kibana 7.0.0 < 7.17.8, 8.0.0 < 8.5.0 RCE Vulnerability (ESA-2022-12)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_elastic_kibana_http_detect.nasl");
  script_mandatory_keys("elastic/kibana/detected");

  script_tag(name:"summary", value:"Kibana is prone to a remote code execution (RCE)
  vulnerability in the headless Chromium browser that Kibana relies on for its reporting capabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability in Chromium is not exploitable on its own but
  could be exploited via an additional cross-site scripting (XSS) in some of affected versions of
  Kibana with the worst impact being remote code execution (RCE) with an attacker executing
  arbitrary commands with permissions of the Kibana process.");

  script_tag(name:"affected", value:"Kibana version 7.0.0 prior to 7.17.8 and 8.0.0 prior to 8.5.0.");

  script_tag(name:"solution", value:"Update to version 7.17.8, 8.5.0 or later.");

  script_xref(name:"URL", value:"https://discuss.elastic.co/t/7-17-8-8-5-0-security-update/320920");

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

if (version_in_range_exclusive(version: version, test_version_lo: "7.0.0", test_version_up: "7.17.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.17.8", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "8.0.0", test_version_up: "8.5.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.5.0", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
