# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:phpmyfaq:phpmyfaq";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124278");
  script_version("2025-09-19T15:40:40+0000");
  script_tag(name:"last_modification", value:"2025-09-19 15:40:40 +0000 (Fri, 19 Sep 2025)");
  script_tag(name:"creation_date", value:"2023-02-13 07:48:56 +0000 (Mon, 13 Feb 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-02-23 05:10:00 +0000 (Thu, 23 Feb 2023)");

  script_cve_id("CVE-2023-0786", "CVE-2023-0787", "CVE-2023-0788", "CVE-2023-0789",
                "CVE-2023-0790", "CVE-2023-0791", "CVE-2023-0792", "CVE-2023-0793",
                "CVE-2023-0794");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("phpMyFAQ < 3.1.11 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_phpmyfaq_http_detect.nasl");
  script_mandatory_keys("phpmyfaq/detected");

  script_tag(name:"summary", value:"phpMyFAQ is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2023-0786, CVE-2023-0787: Cross-site scripting (XSS) - generic in GitHub repository
  thorsten/phpmyfaq.

  - CVE-2023-0788, CVE-2023-0792: Code injection in GitHub repository thorsten/phpmyfaq

  - CVE-2023-0789: Command injection in GitHub repository thorsten/phpmyfaq

  - CVE-2023-0790: Uncaught exception in GitHub repository thorsten/phpmyfaq

  - CVE-2023-0791, CVE-2023-0794: Cross-site scripting (XSS) - stored in GitHub repository
  thorsten/phpmyfaq

  - CVE-2023-0793: Weak password requirements in GitHub repository thorsten/phpmyfaq");

  script_tag(name:"impact", value:"Attacker can execute javascript, send queries with abusive
  words, steal the cookie or redirect to any URL.");

  script_tag(name:"affected", value:"phpMyFAQ prior to version 3.1.11.");

  script_tag(name:"solution", value:"Update to version 3.1.11 or later.");

  script_xref(name:"URL", value:"https://huntr.dev/bounties/8c74ccab-0d1d-4c6b-a0fa-803aa65de04f");
  script_xref(name:"URL", value:"https://huntr.dev/bounties/87397c71-7b84-4617-a66e-fa6c73be9024");
  script_xref(name:"URL", value:"https://huntr.dev/bounties/808d5452-607c-4af1-812f-26c49faf3e61");
  script_xref(name:"URL", value:"https://huntr.dev/bounties/06af150b-b481-4248-9a48-56ded2814156");
  script_xref(name:"URL", value:"https://huntr.dev/bounties/7152b340-c6f3-4ac8-9f62-f764a267488d");
  script_xref(name:"URL", value:"https://huntr.dev/bounties/9e21156b-ab1d-4c60-88ef-8c9f3e2feb7f");
  script_xref(name:"URL", value:"https://huntr.dev/bounties/b3881a1f-2f1e-45cb-86f3-735f66e660e9");
  script_xref(name:"URL", value:"https://huntr.dev/bounties/949975f1-271d-46aa-85e5-1a013cdb5efb");

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

if (version_is_less(version: version, test_version: "3.1.11")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.1.11", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
