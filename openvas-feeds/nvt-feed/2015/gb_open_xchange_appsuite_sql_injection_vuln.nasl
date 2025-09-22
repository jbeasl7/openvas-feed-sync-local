# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:open-xchange:open-xchange_appsuite";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806069");
  script_version("2024-02-20T05:05:48+0000");
  script_cve_id("CVE-2014-7871");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-20 05:05:48 +0000 (Tue, 20 Feb 2024)");
  script_tag(name:"creation_date", value:"2015-10-05 16:02:56 +0530 (Mon, 05 Oct 2015)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Open-Xchange (OX) App Suite SQL Injection Vulnerability (Oct 2015)");

  script_tag(name:"summary", value:"Open-Xchange (OX) App Suite is prone to an SQL injection (SQLi) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to 'ExtractValue' function
  allows execution of arbitrary SQL code by passing it through MySQLs XPath
  interpreter.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  authenticated users to execute arbitrary SQL commands via a crafted
  'jslob API call'.");

  script_tag(name:"affected", value:"Open-Xchange (OX) App Suite versions before
  7.4.2-rev36 and 7.6.x before 7.6.0-rev23.");

  script_tag(name:"solution", value:"Update to version 7.4.2-rev36 or 7.6.0-rev23 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/129020");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/70982");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/533936/100/0/threaded");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_open-xchange_ox_app_suite_http_detect.nasl");
  script_mandatory_keys("open-xchange/app_suite/detected");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!revision = get_kb_item("open-xchange/app_suite/" + port + "/revision"))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];
version += "." + revision;

if(version_is_less(version: version, test_version: "7.4.2.36"))
  fix = "7.4.2-rev36";

else if(version =~ "^7\.6" && version_in_range(version: version, test_version: "7.6.0", test_version2: "7.6.0.22"))
  fix = "7.6.0-rev23";

if (fix) {
  report = report_fixed_ver(installed_version: version, fixed_version: fix, install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
