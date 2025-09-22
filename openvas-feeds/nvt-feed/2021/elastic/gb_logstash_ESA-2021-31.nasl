# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:elastic:logstash";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.147312");
  script_version("2025-09-03T14:11:39+0000");
  script_tag(name:"last_modification", value:"2025-09-03 14:11:39 +0000 (Wed, 03 Sep 2025)");
  script_tag(name:"creation_date", value:"2021-12-13 05:03:51 +0000 (Mon, 13 Dec 2021)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-12-14 01:15:00 +0000 (Tue, 14 Dec 2021)");

  script_cve_id("CVE-2021-44228", "CVE-2021-45046");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Elastic Logstash Multiple Log4j Vulnerabilities (ESA-2021-31, Log4Shell)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_elastic_logstash_consolidation.nasl");
  script_mandatory_keys("elastic/logstash/detected");

  script_tag(name:"summary", value:"Elastic Logstash is prone to multiple vulnerabilities in
  the Apache Log4j library.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  CVE-2021-44228: Apache Log4j2 JNDI features used in configuration, log messages, and parameters do
  not protect against attacker controlled LDAP and other JNDI related endpoints. An attacker who can
  control log messages or log message parameters can execute arbitrary code loaded from LDAP servers
  when message lookup substitution is enabled. This vulnerability is dubbed 'Log4Shell'.

  CVE-2021-45046: Denial of Service (DoS) and a possible remote code execution (RCE) in certain
  non-default configurations.");

  script_tag(name:"impact", value:"The vendor states that there is no impact for CVE-2021-45046 in
  all currently supported versions with default configurations. To avoid unknown risks it is still
  recommended to apply the update provided by the vendor.");

  script_tag(name:"affected", value:"Elastic Logstash version 5.x through 7.x.");

  script_tag(name:"solution", value:"Update to version 6.8.21, 7.16.1 or later.");

  script_xref(name:"URL", value:"https://discuss.elastic.co/t/apache-log4j2-remote-code-execution-rce-vulnerability-cve-2021-44228-esa-2021-31/291476");
  script_xref(name:"URL", value:"https://discuss.elastic.co/t/logstash-5-0-0-6-8-20-and-7-0-0-7-16-0-log4j-cve-2021-44228-cve-2021-45046-remediation/292343");
  script_xref(name:"URL", value:"https://logging.apache.org/log4j/2.x/security.html");
  script_xref(name:"URL", value:"https://github.com/advisories/GHSA-jfh8-c2jp-5v3q");
  script_xref(name:"URL", value:"https://github.com/advisories/GHSA-7rjr-3q55-vv33");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2021/12/10/1");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2021/12/14/4");
  script_xref(name:"URL", value:"https://www.lunasec.io/docs/blog/log4j-zero-day/");
  script_xref(name:"URL", value:"https://www.lunasec.io/docs/blog/log4j-zero-day-update-on-cve-2021-45046/");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");

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

if (version_in_range(version: version, test_version: "5.0", test_version2: "6.8.20")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.8.21", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "7.0", test_version2: "7.16.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.16.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
