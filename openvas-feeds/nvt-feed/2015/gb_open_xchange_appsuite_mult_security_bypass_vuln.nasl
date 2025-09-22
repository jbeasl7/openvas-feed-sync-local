# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:open-xchange:open-xchange_appsuite";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806073");
  script_version("2024-06-28T05:05:33+0000");
  script_cve_id("CVE-2014-2391", "CVE-2014-2392");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-06-28 05:05:33 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"creation_date", value:"2015-10-06 12:24:33 +0530 (Tue, 06 Oct 2015)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Open-Xchange (OX) App Suite Multiple Security Bypass Vulnerabilities (Oct 2015)");

  script_tag(name:"summary", value:"Open-Xchange (OX) App Suite is prone to multiple security bypass vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to password
  recovery service and E-Mail autoconfiguration feature does not handle password
  properly.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to obtain potentially useful password-pattern information.");

  script_tag(name:"affected", value:"Open-Xchange (OX) App Suite versions before
  7.2.2-rev20, 7.4.1 before 7.4.1-rev11, and 7.4.2 before 7.4.2-rev13");

  script_tag(name:"solution", value:"Upgrade to Open-Xchange (OX) AppSuite
  version 7.2.2-rev20, 7.4.1-rev11, 7.4.2-rev13 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/531762");

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

if(version_is_less(version: version, test_version: "7.2.2.20"))
  fix = "7.2.2.20";

else if(version_in_range(version: version, test_version: "7.4.2", test_version2: "7.4.2.12"))
  fix = "7.4.2.13";

else if(version_in_range(version: version, test_version: "7.4.1", test_version2: "7.4.1.10"))
  fix = "7.4.1.11";

if (fix) {
  report = report_fixed_ver(installed_version: version, fixed_version: fix, install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
