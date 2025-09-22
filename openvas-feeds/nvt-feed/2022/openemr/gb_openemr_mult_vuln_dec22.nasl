# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:open-emr:openemr";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127284");
  script_version("2025-05-09T05:40:06+0000");
  script_tag(name:"last_modification", value:"2025-05-09 05:40:06 +0000 (Fri, 09 May 2025)");
  script_tag(name:"creation_date", value:"2022-12-19 08:04:08 +0000 (Mon, 19 Dec 2022)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-12-16 15:09:00 +0000 (Fri, 16 Dec 2022)");

  script_cve_id("CVE-2022-4502", "CVE-2022-4503", "CVE-2022-4504", "CVE-2022-4505",
                "CVE-2022-4506", "CVE-2022-4567", "CVE-2022-4615");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OpenEMR < 7.0.0.2 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_openemr_http_detect.nasl");
  script_mandatory_keys("openemr/detected");

  script_tag(name:"summary", value:"OpenEMR is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2022-4502: Multiple cross-site scripting (XSS) vulnerabilities in Messages Module

  - CVE-2022-4503: Reflected cross-site scripting (XSS) vulnerability in Front Payment CC

  - CVE-2022-4504: Improper name input validation in Upload Document Form

  - CVE-2022-4505: Improper access control vulnerability disclose other user's appointment.

  - CVE-2022-4506: Unrestricted upload of file with dangerous type

  - CVE-2022-4567: Broken access controls in Patient Files

  - CVE-2022-4615: Reflected cross-site scripting (XSS) in fee_sheet_ajax.php

  - No CVE: Unauthenticated arbitrary file read via the user-controlled parameter `$state`

  - No CVE: Authenticated local file inclusion (LFI) via not sanitized user-controlled variable

  - No CVE: Authenticated reflected cross-site scripting (XSS) via uploaded PHP file");

  script_tag(name:"affected", value:"OpenEMR version prior to 7.0.0.2.");

  script_tag(name:"solution", value:"Update to version 7.0.0.2 or later.");

  script_xref(name:"URL", value:"https://huntr.dev/bounties/5bdef791-6886-4008-b9ba-045cb4524114/");
  script_xref(name:"URL", value:"https://huntr.dev/bounties/4cba644c-a2f5-4ed7-af5d-f2cab1895e13/");
  script_xref(name:"URL", value:"https://huntr.dev/bounties/f50538cb-99d3-411d-bd1a-5f36d1fa9f5d/");
  script_xref(name:"URL", value:"https://huntr.dev/bounties/e36ca754-bb9f-4686-ad72-7fb849e97d92/");
  script_xref(name:"URL", value:"https://huntr.dev/bounties/f423d193-4ab0-4f03-ad90-25e4f02e7942/");
  script_xref(name:"URL", value:"https://huntr.dev/bounties/1ac677c4-ec0a-4788-9465-51d9b6bd8fd2/");
  script_xref(name:"URL", value:"https://huntr.dev/bounties/9c66ece4-bcaa-417d-8b98-e8daff8a728b/");
  script_xref(name:"URL", value:"https://www.sonarsource.com/blog/openemr-remote-code-execution-in-your-healthcare-system/");

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

if (version_is_less(version: version, test_version: "7.0.0.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.0.0.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
