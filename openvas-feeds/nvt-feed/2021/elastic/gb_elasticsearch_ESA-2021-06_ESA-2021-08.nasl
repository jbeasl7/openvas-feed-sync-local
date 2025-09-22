# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:elastic:elasticsearch";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.145940");
  script_version("2025-09-03T08:26:15+0000");
  script_tag(name:"last_modification", value:"2025-09-03 08:26:15 +0000 (Wed, 03 Sep 2025)");
  script_tag(name:"creation_date", value:"2021-05-14 04:26:15 +0000 (Fri, 14 May 2021)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-25 06:15:00 +0000 (Fri, 25 Jun 2021)");

  script_cve_id("CVE-2021-22135", "CVE-2021-22137");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Elastic Elasticsearch Multiple Vulnerabilities (ESA-2021-06, ESA-2021-08)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_elastic_elasticsearch_consolidation.nasl");
  script_mandatory_keys("elastic/elasticsearch/detected");

  script_tag(name:"summary", value:"Elasticsearch is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2021-22135: Suggester & Profile API information disclosure flaw

  - CVE-2021-22137: Field disclosure flaw");

  script_tag(name:"impact", value:"This could lead to disclosing the existence of documents and
  fields the attacker should not be able to view or result in an attacker gaining additional insight
  into potentially sensitive indices.");

  script_tag(name:"affected", value:"Elasticsearch versions prior to versions 6.8.15 or 7.12.0.");

  script_tag(name:"solution", value:"Update to version 6.8.15, 7.12.0 or later.");

  script_xref(name:"URL", value:"https://discuss.elastic.co/t/elastic-stack-7-12-0-and-6-8-15-security-update/268125");

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

if (version_is_less(version: version, test_version: "6.8.15")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.8.15", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version =~ "7\." && version_is_less(version: version, test_version: "7.12.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.12.0", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
