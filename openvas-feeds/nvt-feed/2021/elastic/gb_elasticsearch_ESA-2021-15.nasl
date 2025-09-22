# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:elastic:elasticsearch";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.146386");
  script_version("2025-09-03T08:26:15+0000");
  script_tag(name:"last_modification", value:"2025-09-03 08:26:15 +0000 (Wed, 03 Sep 2025)");
  script_tag(name:"creation_date", value:"2021-07-27 07:47:03 +0000 (Tue, 27 Jul 2021)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-08-04 13:56:00 +0000 (Wed, 04 Aug 2021)");

  script_cve_id("CVE-2021-22144");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Elastic Elasticsearch DoS Vulnerability (ESA-2021-15)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_elastic_elasticsearch_consolidation.nasl");
  script_mandatory_keys("elastic/elasticsearch/detected");

  script_tag(name:"summary", value:"Elasticsearch is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An uncontrolled recursion vulnerability that could lead to a
  denial of service attack was identified in the Elasticsearch Grok parser. A user with the ability
  to submit arbitrary queries to Elasticsearch could create a malicious Grok query that will crash
  the Elasticsearch node.");

  script_tag(name:"affected", value:"Elasticsearch prior to version 6.8.17 and 7.x prior to 7.13.3.");

  script_tag(name:"solution", value:"Update to version 6.8.17, 7.13.3 or later.");

  script_xref(name:"URL", value:"https://discuss.elastic.co/t/elasticsearch-7-13-3-and-6-8-17-security-update/278100");

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

if (version_is_less(version: version, test_version: "6.8.17")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.8.17", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "7.0", test_version2: "7.13.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.13.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
