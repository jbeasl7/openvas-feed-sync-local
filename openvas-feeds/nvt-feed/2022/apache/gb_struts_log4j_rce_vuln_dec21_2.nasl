# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:struts";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.117904");
  script_version("2025-05-15T05:40:37+0000");
  script_tag(name:"last_modification", value:"2025-05-15 05:40:37 +0000 (Thu, 15 May 2025)");
  script_tag(name:"creation_date", value:"2022-01-19 07:00:46 +0000 (Wed, 19 Jan 2022)");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-12-21 00:15:00 +0000 (Tue, 21 Dec 2021)");

  script_cve_id("CVE-2021-45046");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Struts 2.5.x < 2.5.28.1 Log4j RCE Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_apache_struts_consolidation.nasl");
  script_mandatory_keys("apache/struts/detected");

  script_tag(name:"summary", value:"Apache Struts is prone to a remote code execution (RCE)
  vulnerability in the Apache Log4j library.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"It was found that the fix to address CVE-2021-44228 in Apache
  Log4j 2.15.0 was incomplete in certain non-default configurations. This could allow attackers with
  control over Thread Context Map (MDC) input data when the logging configuration uses a non-default
  Pattern Layout with either a Context Lookup (for example, $${ctx:loginId}) or a Thread Context Map
  pattern (%X, %mdc, or %MDC) to craft malicious input data using a JNDI Lookup pattern resulting in
  an information leak and remote code execution in some environments and local code execution in all
  environments.");

  script_tag(name:"affected", value:"Apache Struts version 2.5.x prior to 2.5.28.1.");

  script_tag(name:"solution", value:"Update to version 2.5.28.1 or later.");

  script_xref(name:"URL", value:"https://struts.apache.org/announce-2021#a20211217");
  script_xref(name:"URL", value:"https://logging.apache.org/log4j/2.x/security.html");
  script_xref(name:"URL", value:"https://github.com/advisories/GHSA-7rjr-3q55-vv33");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2021/12/14/4");
  script_xref(name:"URL", value:"https://www.lunasec.io/docs/blog/log4j-zero-day-update-on-cve-2021-45046/");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range_exclusive(version: version, test_version_lo: "2.5.0", test_version_up: "2.5.28.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.5.28.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
