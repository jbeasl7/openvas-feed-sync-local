# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:jspwiki";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.147360");
  script_version("2025-05-15T05:40:37+0000");
  script_tag(name:"last_modification", value:"2025-05-15 05:40:37 +0000 (Thu, 15 May 2025)");
  script_tag(name:"creation_date", value:"2021-12-20 08:24:25 +0000 (Mon, 20 Dec 2021)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-12-14 01:15:00 +0000 (Tue, 14 Dec 2021)");

  script_cve_id("CVE-2021-44228");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache JSPWiki 2.11.0 Log4j RCE Vulnerability (Log4Shell) - Version Check");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_apache_jspwiki_http_detect.nasl");
  script_mandatory_keys("apache/jspwiki/detected");

  script_tag(name:"summary", value:"Apache JSPWiki is prone to a remote code execution (RCE)
  vulnerability in the Apache Log4j library dubbed 'Log4Shell'.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Apache Log4j2 JNDI features used in configuration, log messages,
  and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints.
  An attacker who can control log messages or log message parameters can execute arbitrary code
  loaded from LDAP servers when message lookup substitution is enabled.");

  script_tag(name:"affected", value:"Apache JSPWiki version 2.11.0 only.");

  script_tag(name:"solution", value:"Update to version 2.11.1 or later.");

  script_xref(name:"URL", value:"https://jspwiki-wiki.apache.org/Wiki.jsp?page=Log4J-CVE-2021-44228");
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

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version =~ "^2\.11\.0") {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.11.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
