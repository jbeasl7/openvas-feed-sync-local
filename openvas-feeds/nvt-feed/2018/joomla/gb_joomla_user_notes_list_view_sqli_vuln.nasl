# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:joomla:joomla";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812834");
  script_version("2023-07-20T05:05:17+0000");
  script_cve_id("CVE-2018-8045");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-04-09 12:25:00 +0000 (Mon, 09 Apr 2018)");
  script_tag(name:"creation_date", value:"2018-03-20 11:51:14 +0530 (Tue, 20 Mar 2018)");

  script_name("Joomla 'User Notes list view' SQL Injection Vulnerability");

  script_tag(name:"summary", value:"Joomla is prone to an SQL injection (SQLi) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to Joomla's lack of type casting of a
  variable in a SQL statement in 'User Notes list view'.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker to conduct SQL
  injection in the user notes list view.");

  script_tag(name:"affected", value:"Joomla versions 3.5.0 through 3.8.5.");

  script_tag(name:"solution", value:"Update to version 3.8.6 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"https://developer.joomla.org/security-centre/723-20180301-core-sqli-vulnerability.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/103402");

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

if(version_in_range(version:vers, test_version:"3.5.0", test_version2:"3.8.5")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"3.8.6", install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);