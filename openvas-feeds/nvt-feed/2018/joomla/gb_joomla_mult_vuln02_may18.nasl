# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:joomla:joomla";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813410");
  script_version("2024-02-19T14:37:31+0000");
  script_cve_id("CVE-2018-11324", "CVE-2018-11326", "CVE-2018-11325");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-02-19 14:37:31 +0000 (Mon, 19 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"creation_date", value:"2018-05-23 13:35:14 +0530 (Wed, 23 May 2018)");

  script_name("Joomla Multiple Vulnerabilities (20180507, 20180505, 20180504)");

  script_tag(name:"summary", value:"Joomla is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - A race condition where a session which was expected to be destroyed would
    be recreated.

  - Inadequate input filtering.

  - An error where the web install application would autofill password fields
    after either a form validation error or navigating to a previous install
    step, and displays the plain text password for the administrator account at
    the confirmation screen.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to gain access to sensitive information like password, recreation
  of sessions and conduct XSS attacks.");

  script_tag(name:"affected", value:"Joomla version 3.0.0 through 3.8.7.");

  script_tag(name:"solution", value:"Update to version 3.8.8 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"https://developer.joomla.org/security-centre/733-20180505-core-xss-vulnerabilities-additional-hadering.html");
  script_xref(name:"URL", value:"https://developer.joomla.org/security-centre/732-20180504-core-installer-leaks-plain-text-password-to-local-user.html");
  script_xref(name:"URL", value:"https://developer.joomla.org/security-centre/735-20180507-core-session-deletion-race-condition.html");

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl");
  script_mandatory_keys("joomla/installed");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_in_range(version:vers, test_version:"3.0.0", test_version2:"3.8.7")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"3.8.8", install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
