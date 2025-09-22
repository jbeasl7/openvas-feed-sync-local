# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:elastic:elasticsearch";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.117169");
  script_version("2025-09-03T08:26:15+0000");
  script_tag(name:"last_modification", value:"2025-09-03 08:26:15 +0000 (Wed, 03 Sep 2025)");
  script_tag(name:"creation_date", value:"2021-01-19 14:15:51 +0000 (Tue, 19 Jan 2021)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-09 23:36:00 +0000 (Wed, 09 Oct 2019)");

  script_cve_id("CVE-2018-17247");

  # nb: Only Elasticsearch Security affected. Java Security Manager is also enabled by default
  # which will cause this attack to fail.
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Elastic Elasticsearch Security Information Disclosure Vulnerability (ESA-2018-19)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_elastic_elasticsearch_consolidation.nasl");
  script_mandatory_keys("elastic/elasticsearch/detected");

  script_tag(name:"summary", value:"Elasticsearch Security is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Elasticsearch Security contain an XXE flaw in Machine Learning's
  find_file_structure API. If a policy allowing external network access has been added to Elasticsearch's
  Java Security Manager then an attacker could send a specially crafted request capable of leaking content
  of local files on the Elasticsearch node.

  Please note: by default Elasticsearch has the Java Security Manager enabled with policies which will
  cause this attack to fail.");

  script_tag(name:"impact", value:"This flaw could allow users to access information that they should
  not have access to.");

  script_tag(name:"affected", value:"Elasticsearch Security versions 6.5.0 and 6.5.1.");

  script_tag(name:"solution", value:"Update to version 6.5.2 or later.");

  script_xref(name:"URL", value:"https://discuss.elastic.co/t/elastic-stack-6-5-2-security-update/159594");
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

if (version_in_range(version: version, test_version: "6.5.0", test_version2: "6.5.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.5.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
