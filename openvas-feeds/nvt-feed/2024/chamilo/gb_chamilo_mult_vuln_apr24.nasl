# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:chamilo:chamilo_lms";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.128069");
  script_version("2025-03-04T05:38:25+0000");
  script_tag(name:"last_modification", value:"2025-03-04 05:38:25 +0000 (Tue, 04 Mar 2025)");
  script_tag(name:"creation_date", value:"2024-12-10 07:47:25 +0000 (Tue, 10 Dec 2024)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_cve_id("CVE-2024-30616", "CVE-2024-30617", "CVE-2024-30618", "CVE-2024-30619");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_name("Chamilo LMS 1.11.x <= 1.11.26 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_chamilo_http_detect.nasl");
  script_mandatory_keys("chamilo/detected");

  script_tag(name:"summary", value:"Chamilo LMS is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2024-30616: Incorrect access control via main/auth/profile

  - CVE-2024-30617: Cross-site request forgery in main/social/home.php

  - CVE-2024-30618: Stored cross-site scripting

  - CVE-2024-30619: Incorrect access control");

  script_tag(name:"affected", value:"Chamilo LMS version 1.11.x through 1.11.26.");

  script_tag(name:"solution", value:"No known solution is available as of 10th December, 2024.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://github.com/bahadoumi/Vulnerability-Research/tree/main/CVE-2024-30616");
  script_xref(name:"URL", value:"https://github.com/bahadoumi/Vulnerability-Research/tree/main/CVE-2024-30617");
  script_xref(name:"URL", value:"https://github.com/bahadoumi/Vulnerability-Research/tree/main/CVE-2024-30618");
  script_xref(name:"URL", value:"https://github.com/bahadoumi/Vulnerability-Research/tree/main/CVE-2024-30619");

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

if (version_in_range(version: version, test_version: "1.11.0", test_version2: "1.11.26")) {
   report = report_fixed_ver(installed_version: version, fixed_version: "NoneAvailable", install_path: location);
   security_message(port: port, data: report);
   exit(0);
}

exit(0);