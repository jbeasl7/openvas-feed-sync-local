# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:elastic:kibana";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.145942");
  script_version("2025-09-03T14:11:39+0000");
  script_tag(name:"last_modification", value:"2025-09-03 14:11:39 +0000 (Wed, 03 Sep 2025)");
  script_tag(name:"creation_date", value:"2021-05-14 04:57:22 +0000 (Fri, 14 May 2021)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-05-21 16:37:00 +0000 (Fri, 21 May 2021)");

  script_cve_id("CVE-2021-22139");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Elastic Kibana DoS Vulnerability (ESA-2021-10)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_elastic_kibana_http_detect.nasl");
  script_mandatory_keys("elastic/kibana/detected");

  script_tag(name:"summary", value:"Kibana is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A DoS vulnerability was found in the Kibana webhook actions due
  to a lack of timeout or a limit on the request size. An attacker with permissions to create
  webhook actions could drain the Kibana host connection pool, making Kibana unavailable for all
  other users.");

  script_tag(name:"affected", value:"Kibana version 7.12.0 and prior.");

  script_tag(name:"solution", value:"Update to version 7.12.1 or later.");

  script_xref(name:"URL", value:"https://discuss.elastic.co/t/7-12-1-security-update/271433");

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

if (version_is_less(version: version, test_version: "7.12.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.12.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
