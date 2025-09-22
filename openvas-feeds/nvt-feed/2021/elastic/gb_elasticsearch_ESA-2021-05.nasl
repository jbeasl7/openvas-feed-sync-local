# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:elastic:elasticsearch";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.145568");
  script_version("2025-09-03T08:26:15+0000");
  script_tag(name:"last_modification", value:"2025-09-03 08:26:15 +0000 (Wed, 03 Sep 2025)");
  script_tag(name:"creation_date", value:"2021-03-11 06:22:51 +0000 (Thu, 11 Mar 2021)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-05-05 13:28:00 +0000 (Wed, 05 May 2021)");

  script_cve_id("CVE-2021-22134");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Elastic Elasticsearch Information Disclosure Vulnerability (ESA-2021-05)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_elastic_elasticsearch_consolidation.nasl");
  script_mandatory_keys("elastic/elasticsearch/detected");

  script_tag(name:"summary", value:"Elasticsearch is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A document disclosure flaw was found in Elasticsearch when Document or
  Field Level Security is used. Get requests do not properly apply security permissions when executing a query
  against a recently updated document. This affects documents that have been updated and not yet refreshed in
  the index.");

  script_tag(name:"impact", value:"This could result in the search disclosing the existence of documents and
  fields the attacker should not be able to view. A mitigating factor to this flaw is an attacker must know
  the document ID to run the get request.");

  script_tag(name:"affected", value:"Elasticsearch versions after 7.6.0 and before 7.11.0.");

  script_tag(name:"solution", value:"Update to version 7.11.0 or later.");

  script_xref(name:"URL", value:"https://discuss.elastic.co/t/elastic-stack-7-11-0-security-update/265835");

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

if (version_is_greater(version: version, test_version: "7.6.0") &&
    version_is_less(version: version, test_version: "7.11.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.11.0", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
