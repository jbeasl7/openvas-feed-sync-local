# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:elastic:logstash";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143052");
  script_version("2025-09-03T14:11:39+0000");
  script_tag(name:"last_modification", value:"2025-09-03 14:11:39 +0000 (Wed, 03 Sep 2025)");
  script_tag(name:"creation_date", value:"2019-11-05 03:04:11 +0000 (Tue, 05 Nov 2019)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-09 12:55:00 +0000 (Fri, 09 Oct 2020)");

  script_cve_id("CVE-2019-7620");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Elastic Logstash Beats Input Plugin DoS Vulnerability (ESA-2019-14)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_elastic_logstash_consolidation.nasl");
  script_mandatory_keys("elastic/logstash/detected");

  script_tag(name:"summary", value:"A denial of service flaw was found in the Logstash beats input plugin.");

  script_tag(name:"impact", value:"An unauthenticated user who is able to connect to the port the Logstash beats
  input could send a specially crafted network packet that would cause Logstash to stop responding.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Logstash versions before 6.8.4 and 7.4.1.");

  script_tag(name:"solution", value:"Update to version 6.8.4, 7.4.1 or later.");

  script_xref(name:"URL", value:"https://discuss.elastic.co/t/elastic-stack-6-8-4-security-update/204908");
  script_xref(name:"URL", value:"https://discuss.elastic.co/t/elastic-stack-7-4-1-security-update/204909");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
path = infos["location"];

if (version_is_less(version: version, test_version: "6.8.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.8.4", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "7.0.0", test_version2: "7.4.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.4.1", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
