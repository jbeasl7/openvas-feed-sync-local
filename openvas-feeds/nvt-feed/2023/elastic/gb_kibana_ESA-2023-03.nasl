# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:elastic:kibana";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126350");
  script_version("2025-09-03T14:11:39+0000");
  script_tag(name:"last_modification", value:"2025-09-03 14:11:39 +0000 (Wed, 03 Sep 2025)");
  script_tag(name:"creation_date", value:"2023-02-20 09:00:34 +0000 (Mon, 20 Feb 2023)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-03-03 14:15:00 +0000 (Fri, 03 Mar 2023)");

  script_cve_id("CVE-2022-38779");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Elastic Kibana 7.0.0 < 7.17.9, 8.0.0 < 8.6.2 Open Redirect Vulnerability (ESA-2023-03)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_elastic_kibana_http_detect.nasl");
  script_mandatory_keys("elastic/kibana/detected");

  script_tag(name:"summary", value:"Kibana is prone to an open redirect vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An open redirect was discovered in Kibana that could lead to a
  user being redirected to an arbitrary website if they use a maliciously crafted Kibana URL.");

  script_tag(name:"affected", value:"Kibana version 7.0.0 prior to 7.17.9 and 8.0.0 prior to 8.6.2.");

  script_tag(name:"solution", value:"Update to version 7.17.9, 8.6.2 or later.");

  script_xref(name:"URL", value:"https://discuss.elastic.co/t/kibana-7-17-9-and-8-6-2-security-update/325782");

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

if (version_in_range_exclusive(version: version, test_version_lo: "7.0.0", test_version_up: "7.17.9")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.17.9", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "8.0.0", test_version_up: "8.6.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.6.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
