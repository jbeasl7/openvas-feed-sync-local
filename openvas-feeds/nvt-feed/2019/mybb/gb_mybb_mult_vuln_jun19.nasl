# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mybb:mybb";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113371");
  script_version("2025-07-01T05:42:02+0000");
  script_tag(name:"last_modification", value:"2025-07-01 05:42:02 +0000 (Tue, 01 Jul 2025)");
  script_tag(name:"creation_date", value:"2019-06-13 09:54:06 +0000 (Thu, 13 Jun 2019)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-06-30 16:52:10 +0000 (Mon, 30 Jun 2025)");

  script_cve_id("CVE-2019-3578", "CVE-2019-3579");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MyBB <= 1.8.19 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("sw_mybb_http_detect.nasl");
  script_mandatory_keys("mybb/detected");

  script_tag(name:"summary", value:"MyBB is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - XSS in the resetpassword function

  - Remote attackers may obtain sensitive information because MyBB discloses the username upon
  receiving a password-reset request that lacks the code parameter.");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to obtain
  sensitive information or inject arbitrary HTML and JavaScript into the site.");

  script_tag(name:"affected", value:"MyBB through version 1.8.19.");

  script_tag(name:"solution", value:"Update to version 1.8.20 or later.");

  script_xref(name:"URL", value:"https://blog.mybb.com/2019/02/27/mybb-1-8-20-released-security-maintenance-release/");

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

if (version_is_less(version: version, test_version: "1.8.20")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.8.20", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
