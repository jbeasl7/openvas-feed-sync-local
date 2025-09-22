# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:elastic:elasticsearch";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.117181");
  script_version("2025-09-03T08:26:15+0000");
  script_tag(name:"last_modification", value:"2025-09-03 08:26:15 +0000 (Wed, 03 Sep 2025)");
  script_tag(name:"creation_date", value:"2021-01-25 13:07:06 +0000 (Mon, 25 Jan 2021)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-11-23 12:15:00 +0000 (Mon, 23 Nov 2020)");

  script_cve_id("CVE-2020-7020");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Elastic Elasticsearch Information Disclosure Vulnerability (ESA-2020-13)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_elastic_elasticsearch_consolidation.nasl");
  script_mandatory_keys("elastic/elasticsearch/detected");

  script_tag(name:"summary", value:"Elasticsearch is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A document disclosure flaw was found in Elasticsearch when Document or
  Field Level Security is used. Search queries do not properly preserve security permissions when executing
  certain complex queries.");

  script_tag(name:"impact", value:"This could result in the search disclosing the existence of documents
  the attacker should not be able to view. This could result in an attacker gaining additional insight
  into potentially sensitive indices.");

  script_tag(name:"affected", value:"Elasticsearch versions before 6.8.13 and 7.x before 7.9.2.");

  script_tag(name:"solution", value:"Update to version 6.8.13, 7.9.2 or later.");

  script_xref(name:"URL", value:"https://discuss.elastic.co/t/elastic-stack-7-9-3-and-6-8-13-security-update/253033");
  script_xref(name:"URL", value:"https://www.elastic.co/community/security");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "6.8.13")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.8.13", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "7.0.0", test_version2: "7.9.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.9.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
