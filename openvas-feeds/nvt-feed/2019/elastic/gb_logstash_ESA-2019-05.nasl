# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:elastic:logstash";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142176");
  script_version("2025-09-16T05:38:45+0000");
  script_tag(name:"last_modification", value:"2025-09-16 05:38:45 +0000 (Tue, 16 Sep 2025)");
  script_tag(name:"creation_date", value:"2019-03-27 21:39:17 +0000 (Wed, 27 Mar 2019)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-05 20:38:00 +0000 (Mon, 05 Oct 2020)");

  script_cve_id("CVE-2019-7612");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Elastic Logstash Information Disclosure Vulnerability (ESA-2019-05)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_elastic_logstash_consolidation.nasl");
  script_mandatory_keys("elastic/logstash/detected");

  script_tag(name:"summary", value:"A sensitive data disclosure flaw was found in the way Logstash logs malformed
  URLs.");

  script_tag(name:"impact", value:"If a malformed URL is specified as part of the Logstash configuration, the
  credentials for the URL could be inadvertently logged as part of the error message.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Logstash versions before 6.6.1 and 5.6.15.");

  script_tag(name:"solution", value:"Update to version 5.6.15, 6.6.1 or later.");

  script_xref(name:"URL", value:"https://discuss.elastic.co/t/elastic-stack-6-6-1-and-5-6-15-security-update/169077");

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

if (version_is_less(version: version, test_version: "5.6.15")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.6.15", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

if (version =~ "^6\.") {
  if (version_is_less(version: version, test_version: "6.6.1")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "6.6.1", install_path: path);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
