# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:elastic:elasticsearch";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.145383");
  script_version("2025-09-03T08:26:15+0000");
  script_tag(name:"last_modification", value:"2025-09-03 08:26:15 +0000 (Wed, 03 Sep 2025)");
  script_tag(name:"creation_date", value:"2021-02-15 05:53:31 +0000 (Mon, 15 Feb 2021)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-03-26 12:49:00 +0000 (Fri, 26 Mar 2021)");

  script_cve_id("CVE-2020-7021");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Elastic Elasticsearch Information Disclosure Vulnerability (ESA-2021-03)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_elastic_elasticsearch_consolidation.nasl");
  script_mandatory_keys("elastic/elasticsearch/detected");

  script_tag(name:"summary", value:"Elasticsearch is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Elasticsearch has an information disclosure issue when audit logging and
  the emit_request_body option is enabled. The Elasticsearch audit log could contain sensitive information
  such as password hashes or authentication tokens.");

  script_tag(name:"impact", value:"This could allow an Elasticsearch administrator to view sensitive details.");

  script_tag(name:"affected", value:"Elasticsearch versions prior to 6.8.14 and 7.0.0 prior to 7.10.0.");

  script_tag(name:"solution", value:"Update to version 6.8.14, 7.10.0 or later.");

  script_xref(name:"URL", value:"https://discuss.elastic.co/t/elastic-stack-7-11-0-and-6-8-14-security-update/263915");
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

if (version_is_less(version: version, test_version: "6.8.14")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.8.14", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version =~ "^7\." && version_is_less(version: version, test_version: "7.10.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.10.0", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
