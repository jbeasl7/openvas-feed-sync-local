# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mybb:mybb";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814216");
  script_version("2025-04-30T05:39:51+0000");
  script_tag(name:"last_modification", value:"2025-04-30 05:39:51 +0000 (Wed, 30 Apr 2025)");
  script_tag(name:"creation_date", value:"2018-09-18 16:04:20 +0530 (Tue, 18 Sep 2018)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-11-07 14:58:00 +0000 (Wed, 07 Nov 2018)");

  script_cve_id("CVE-2018-17128");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MyBB < 1.8.19 Multiple Vulnerabilities (Sep 2018)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("sw_mybb_http_detect.nasl");
  script_mandatory_keys("mybb/detected");

  script_tag(name:"summary", value:"MyBB is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - Insufficient permission check in User CP's attachment management.

  - Insufficient email address verification.

  - Insufficient validation of input in Visual Editor and Email field.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to conduct
  SQL Injection, execute arbitrary javascript code and gain escalated privilege.");

  script_tag(name:"affected", value:"MyBB versions prior to 1.8.19.");

  script_tag(name:"solution", value:"Update to version 1.8.19 or later.");

  script_xref(name:"URL", value:"https://mybb.com/versions/1.8.19");
  script_xref(name:"URL", value:"https://blog.mybb.com/2018/09/11/mybb-1-8-19-released-security-maintenance-release");

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

if (version_is_less(version: version, test_version: "1.8.19")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.8.19", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
