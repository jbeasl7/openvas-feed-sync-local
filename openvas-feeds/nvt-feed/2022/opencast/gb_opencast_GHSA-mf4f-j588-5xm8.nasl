# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:opencast:opencast";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.148715");
  script_version("2025-05-15T05:40:37+0000");
  script_tag(name:"last_modification", value:"2025-05-15 05:40:37 +0000 (Thu, 15 May 2025)");
  script_tag(name:"creation_date", value:"2022-09-12 05:47:58 +0000 (Mon, 12 Sep 2022)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-12-14 01:15:00 +0000 (Tue, 14 Dec 2021)");

  script_cve_id("CVE-2021-44228");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Opencast < 9.10, 10.x < 10.6 Log4j RCE Vulnerability (GHSA-mf4f-j588-5xm8, Log4Shell)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_opencast_detect.nasl");
  script_mandatory_keys("opencast/detected");

  script_tag(name:"summary", value:"Opencast is prone to a remote code execution (RCE) vulnerability
  in the Apache Log4j library dubbed 'Log4Shell'.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Apache Log4j2 JNDI features used in configuration, log messages,
  and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints.
  An attacker who can control log messages or log message parameters can execute arbitrary code
  loaded from LDAP servers when message lookup substitution is enabled.");

  script_tag(name:"affected", value:"Opencast prior to version 9.10 and 10.x prior to version 10.6.");

  script_tag(name:"solution", value:"Update to version 9.10, 10.6 or later.");

  script_xref(name:"URL", value:"https://github.com/opencast/opencast/security/advisories/GHSA-mf4f-j588-5xm8");
  script_xref(name:"URL", value:"https://logging.apache.org/log4j/2.x/security.html");
  script_xref(name:"URL", value:"https://github.com/advisories/GHSA-jfh8-c2jp-5v3q");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2021/12/10/1");
  script_xref(name:"URL", value:"https://www.lunasec.io/docs/blog/log4j-zero-day/");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");

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

if (version_is_less(version: version, test_version: "9.10")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.10", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "10.0", test_version_up: "10.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.6", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
