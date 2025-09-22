# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:elastic:kibana";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126333");
  script_version("2025-09-03T14:11:39+0000");
  script_tag(name:"last_modification", value:"2025-09-03 14:11:39 +0000 (Wed, 03 Sep 2025)");
  script_tag(name:"creation_date", value:"2023-02-06 15:00:34 +0000 (Mon, 06 Feb 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-12-01 20:25:00 +0000 (Thu, 01 Dec 2022)");

  # nb: First CVE is for Kibana, the second CVE is from the component which seems to cause this flaw.
  script_cve_id("CVE-2022-38778", "CVE-2022-38900");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Elastic Kibana 7.0.0 < 7.17.9, 8.0.0 < 8.6.1 DoS Vulnerability (ESA-2023-02)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_elastic_kibana_http_detect.nasl");
  script_mandatory_keys("elastic/kibana/detected");

  script_tag(name:"summary", value:"Elastic Kibana is prone to a denial of service (DoS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A flaw was discovered in one of Kibana's third party
  dependencies, that could allow an authenticated user to perform a request that crashes the Kibana
  server process.");

  script_tag(name:"affected", value:"Elastic Kibana versions 7.0.0 through 7.17.8 and 8.0.0 through
  8.6.0.");

  script_tag(name:"solution", value:"Update to version 7.17.9, 8.6.1 or later.");

  script_xref(name:"URL", value:"https://discuss.elastic.co/t/elastic-7-17-9-8-5-0-and-8-6-1-security-update/324661");

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

if (version_in_range_exclusive(version: version, test_version_lo: "8.0.0", test_version_up: "8.6.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.6.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
