# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:solr";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813555");
  script_version("2024-06-28T15:38:46+0000");
  script_cve_id("CVE-2018-8026");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-06-28 15:38:46 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-29 18:44:00 +0000 (Fri, 29 Mar 2019)");
  script_tag(name:"creation_date", value:"2018-08-02 13:16:18 +0530 (Thu, 02 Aug 2018)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("Apache Solr Multiple XXE Vulnerabilities (SOLR-12450) - Linux");

  script_tag(name:"summary", value:"Apache Solr is prone to multiple XML external entity (XXE)
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to improper sanitization of user input in
  currency.xml, enumsConfig.xml referred from schema.xml, TIKA parsecontext configuration files.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to gain access to
  sensitive information that may lead to further attacks.");

  script_tag(name:"affected", value:"Apache Solr versions from 6.0.0 to 6.6.4 and 7.0.0 to 7.3.1.");

  script_tag(name:"solution", value:"Update to version 6.6.5, 7.4.0 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://mail-archives.apache.org/mod_mbox/lucene-solr-user/201807.mbox/%3C0cdc01d413b7%24f97ba580%24ec72f080%24%40apache.org%3E");
  script_xref(name:"URL", value:"https://issues.apache.org/jira/browse/SOLR-12450");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_apache_solr_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("apache/solr/detected", "Host/runs_unixoide");

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

if (version_in_range(version: version, test_version: "6.0.0", test_version2: "6.6.4"))
  fix = "6.6.5";

else if (version_in_range(version: version, test_version: "7.0.0", test_version2: "7.3.1"))
  fix = "7.4.0";

if(fix) {
  report = report_fixed_ver(installed_version: version, fixed_version: fix, install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
