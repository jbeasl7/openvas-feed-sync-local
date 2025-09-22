# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:elastic:elasticsearch";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.117182");
  script_version("2025-09-03T08:26:15+0000");
  script_tag(name:"last_modification", value:"2025-09-03 08:26:15 +0000 (Wed, 03 Sep 2025)");
  script_tag(name:"creation_date", value:"2021-01-25 13:07:06 +0000 (Mon, 25 Jan 2021)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-02-22 18:40:00 +0000 (Mon, 22 Feb 2021)");

  script_cve_id("CVE-2021-22132");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Elastic Elasticsearch Information Disclosure Vulnerability (ESA-2021-01)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_elastic_elasticsearch_consolidation.nasl");
  script_mandatory_keys("elastic/elasticsearch/detected");

  script_tag(name:"summary", value:"Elasticsearch is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An information disclosure flaw was found in the Elasticsearch async
  search API. Users who execute an async search will store the HTTP headers.");

  script_tag(name:"impact", value:"An Elasticsearch user with the ability to read the .tasks index could
  obtain sensitive request headers of other users in the cluster.");

  script_tag(name:"affected", value:"Elasticsearch versions starting with 7.7.0 and before 7.10.2.");

  script_tag(name:"solution", value:"Update to version 7.10.2 or later.");

  script_xref(name:"URL", value:"https://discuss.elastic.co/t/elasticsearch-7-10-2-security-update/261164");
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

if (version_in_range(version: version, test_version: "7.7.0", test_version2: "7.10.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.10.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
