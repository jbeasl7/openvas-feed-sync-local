# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:trendmicro:smart_protection_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812574");
  script_version("2023-07-20T05:05:18+0000");
  script_cve_id("CVE-2018-6231");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:18 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"creation_date", value:"2018-03-20 10:56:21 +0530 (Tue, 20 Mar 2018)");

  script_name("Trend Micro Smart Protection Server Multiple Vulnerabilities (1119385)");

  script_tag(name:"summary", value:"Trend Micro Smart Protection Server is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaws exist within the handling of credentials provided at login. When
  parsing the username, the process does not properly validate a user-supplied string before using it to
  execute a system call.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker to escalate privileges to
  resources normally protected from the user.");

  script_tag(name:"affected", value:"Trend Micro Smart Protection Server (Standalone) 3.2 and prior.");

  script_tag(name:"solution", value:"Upgrade to Trend Micro Smart Protection Server 3.3 CP1076, 3.2 CP1090,
  3.1 CP1064, 3.0 CP1355 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"https://success.trendmicro.com/solution/1119385");

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Web Servers");
  script_dependencies("gb_trendmicro_smart_protection_server_detect.nasl");
  script_mandatory_keys("trendmicro/sps/detected");
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

if (version_is_less_equal(version: version, test_version: "3.0")) {
  fix = "3.0 CP1355";
}
else if (version == "3.1") {
  fix = "3.1 CP1064";
}
else if (version == "3.2") {
  fix = "3.2 CP1090";
}
else if (version == "3.3") {
  fix = "3.3 CP1076";
}

if (fix) {
  report = report_fixed_ver(installed_version: version, fixed_version:fix,  install_path: location);
  security_message(data: report, port: port);
  exit(0);
}

exit(99);
