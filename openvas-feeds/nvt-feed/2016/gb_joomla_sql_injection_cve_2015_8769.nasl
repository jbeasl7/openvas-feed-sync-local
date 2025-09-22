# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:joomla:joomla";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807032");
  script_version("2024-02-20T05:05:48+0000");
  script_cve_id("CVE-2015-8769");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-20 05:05:48 +0000 (Tue, 20 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-12-07 18:30:00 +0000 (Wed, 07 Dec 2016)");
  script_tag(name:"creation_date", value:"2016-01-19 15:04:54 +0530 (Tue, 19 Jan 2016)");

  script_name("Joomla Core SQL Injection Vulnerability (Jan 2016)");

  script_tag(name:"summary", value:"Joomla is prone to an SQL injection (SQLi) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to inadequate filtering of request data.");

  script_tag(name:"impact", value:"Successfully exploiting this issue allow
  remote attacker to execute arbitrary SQL commands via unspecified vectors.");

  script_tag(name:"affected", value:"Joomla core versions 3.0.0 through 3.4.6");

  script_tag(name:"solution", value:"Upgrade to Joomla version 3.4.7 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"https://developer.joomla.org/security-centre/640-20151207-core-sql-injection.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/79679");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl");
  script_mandatory_keys("joomla/installed");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!jPort = get_app_port(cpe:CPE))
  exit(0);

if(!jVer = get_app_version(cpe:CPE, port:jPort))
  exit(0);

if(version_in_range(version:jVer, test_version:"3.0.0", test_version2:"3.4.6")) {
  report = report_fixed_ver(installed_version: jVer, fixed_version: "3.4.7");
  security_message(data:report, port:jPort);
  exit(0);
}

exit(0);
