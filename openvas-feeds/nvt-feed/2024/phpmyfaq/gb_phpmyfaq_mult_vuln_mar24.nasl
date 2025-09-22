# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:phpmyfaq:phpmyfaq";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126669");
  script_version("2025-09-19T15:40:40+0000");
  script_tag(name:"last_modification", value:"2025-09-19 15:40:40 +0000 (Fri, 19 Sep 2025)");
  script_tag(name:"creation_date", value:"2024-03-26 12:37:15 +0000 (Tue, 26 Mar 2024)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-01-09 17:01:02 +0000 (Thu, 09 Jan 2025)");

  script_cve_id("CVE-2024-27299", "CVE-2024-27300", "CVE-2024-28105", "CVE-2024-28106",
                "CVE-2024-28107", "CVE-2024-28108", "CVE-2024-29179", "CVE-2024-29196");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("phpMyFAQ < 3.2.6 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_phpmyfaq_http_detect.nasl");
  script_mandatory_keys("phpmyfaq/detected");

  script_tag(name:"summary", value:"phpMyFAQ is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2024-27299: An SQL injection in the 'Add News' functionality due to improper escaping of the
  email address. This allows any authenticated user with the rights to add/edit FAQ news to exploit
  this vulnerability to exfiltrate data, take over accounts and in some cases, even achieve RCE.

  - CVE-2024-27300: The email field in phpMyFAQ's user control panel page is vulnerable to stored
  XSS attacks due to the inadequacy of PHP's FILTER_VALIDATE_EMAIL function, which only validates
  the email format, not its content.

  - CVE-2024-28105: The category image upload function in phpmyfaq is vulnerable to manipulation of
  the Content-type and lang parameters, allowing attackers to upload malicious files with a .php
  extension, potentially leading to remote code execution (RCE) on the system.

  - CVE-2024-28106: By manipulating the news parameter in a POST request, an attacker can inject
  malicious JavaScript code. Upon browsing to the compromised news page, the XSS payload triggers.

  - CVE-2024-28107: An SQL injection in the insertentry & saveentr when modifying records due to
  improper escaping of the email address. This allows any authenticated user with the rights to
  add/edit FAQ news to exploit this vulnerability to exfiltrate data, take over accounts and in some
  cases, even achieve RCE.

  - CVE-2024-28108: Due to insufficient validation on the contentLink parameter, it is possible for
  unauthenticated users to inject HTML code to the page which might affect other users. Also,
  requires that adding new FAQs is allowed for guests and that the admin doesn't check the content
  of a newly added FAQ.

  - CVE-2024-29179: An attacker with admin privileges can upload an attachment containing JS code
  without extension and the application will render it as HTML which allows for XSS attacks.

  - CVE-2024-29196: There is a Path Traversal vulnerability in Attachments that allows attackers
  with admin rights to upload malicious files to other locations of the web root.");

  script_tag(name:"affected", value:"phpMyFAQ prior to version 3.2.6.");

  script_tag(name:"solution", value:"Update to version 3.2.6 or later.");

  script_xref(name:"URL", value:"https://www.phpmyfaq.de/security/advisory-2024-03-25");
  script_xref(name:"URL", value:"https://github.com/thorsten/phpMyFAQ/security/advisories/GHSA-qgxx-4xv5-6hcw");
  script_xref(name:"URL", value:"https://github.com/thorsten/phpMyFAQ/security/advisories/GHSA-q7g6-xfh2-vhpx");
  script_xref(name:"URL", value:"https://github.com/thorsten/phpMyFAQ/security/advisories/GHSA-pwh2-fpfr-x5gf");
  script_xref(name:"URL", value:"https://github.com/thorsten/phpMyFAQ/security/advisories/GHSA-6p68-36m6-392r");
  script_xref(name:"URL", value:"https://github.com/thorsten/phpMyFAQ/security/advisories/GHSA-2grw-mc9r-822r");
  script_xref(name:"URL", value:"https://github.com/thorsten/phpMyFAQ/security/advisories/GHSA-48vw-jpf8-hwqh");
  script_xref(name:"URL", value:"https://github.com/thorsten/phpMyFAQ/security/advisories/GHSA-hm8r-95g3-5hj9");
  script_xref(name:"URL", value:"https://github.com/thorsten/phpMyFAQ/security/advisories/GHSA-mmh6-5cpf-2c72");

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

if (version_is_less(version: version, test_version: "3.2.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.2.6", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
