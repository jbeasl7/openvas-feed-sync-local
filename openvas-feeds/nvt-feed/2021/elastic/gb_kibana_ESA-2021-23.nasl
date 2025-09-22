# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:elastic:kibana";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.117700");
  script_version("2025-09-03T14:11:39+0000");
  script_tag(name:"last_modification", value:"2025-09-03 14:11:39 +0000 (Wed, 03 Sep 2025)");
  script_tag(name:"creation_date", value:"2021-09-27 11:31:59 +0000 (Mon, 27 Sep 2021)");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-11-22 20:28:00 +0000 (Tue, 22 Nov 2022)");

  script_cve_id("CVE-2021-37936");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Elastic Kibana HTML Injection Vulnerability (ESA-2021-23)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_elastic_kibana_http_detect.nasl");
  script_mandatory_keys("elastic/kibana/detected");

  script_tag(name:"summary", value:"Elastic Kibana is prone to an HTML injection vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that kibana was not sanitizing document fields
  containing html snippets. Using this vulnerability, an attacker with the ability to write
  documents to an elasticsearch index could inject HTML. When the Discover app highlighted a search
  term containing the HTML, it would be rendered for the user.");

  script_tag(name:"affected", value:"Elastic Kibana version 7.14.0 only.");

  script_tag(name:"solution", value:"Update to version 7.14.1 or later.

  Mitigation: Users can set 'doc_table:highlight' to 'false' in the Kibana Advanced Settings.");

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

if (version_is_equal(version: version, test_version: "7.14.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.14.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
