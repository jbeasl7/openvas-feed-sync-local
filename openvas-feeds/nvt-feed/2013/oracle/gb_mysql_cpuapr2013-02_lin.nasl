# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:oracle:mysql";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803484");
  script_version("2025-09-09T05:38:49+0000");
  script_tag(name:"last_modification", value:"2025-09-09 05:38:49 +0000 (Tue, 09 Sep 2025)");
  script_tag(name:"creation_date", value:"2013-04-22 16:38:19 +0530 (Mon, 22 Apr 2013)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_cve_id("CVE-2013-2375", "CVE-2013-1544", "CVE-2013-1532", "CVE-2013-2389", "CVE-2013-2392",
                "CVE-2013-2391");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Oracle MySQL Server <= 5.1.68 / 5.5 <= 5.5.30 / 5.6 <= 5.6.10 Security Update (cpuapr2013) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Databases");
  script_dependencies("gb_mysql_mariadb_remote_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("oracle/mysql/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Oracle MySQL Server is prone to multiple unspecified vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to affect
  confidentiality, integrity, and availability via unknown vectors.");

  script_tag(name:"insight", value:"Unspecified error in Server Optimizer, Server Privileges, InnoDB, and in
  some unspecified vectors.");

  script_tag(name:"affected", value:"Oracle MySQL Server versions 5.1.68 and prior, 5.5 through 5.5.30 and 5.6 through 5.6.10.");

  script_tag(name:"solution", value:"Update to version 5.1.69, 5.5.31, 5.6.11 or later.");

  script_xref(name:"URL", value:"https://www.oracle.com/security-alerts/cpuapr2013.html#AppendixMSQL");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59207");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59209");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59224");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59242");
  script_xref(name:"Advisory-ID", value:"cpuapr2013");

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

if (version_is_less_equal(version: version, test_version: "5.1.68")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.1.69", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

else if (version_in_range(version: version, test_version: "5.5", test_version2: "5.5.30")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.5.31", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

else if (version_in_range(version: version, test_version: "5.6", test_version2: "5.6.10")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.6.11", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
