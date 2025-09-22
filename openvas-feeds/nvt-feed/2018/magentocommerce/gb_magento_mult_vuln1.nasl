# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:magentocommerce:magento";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140649");
  script_version("2025-09-05T15:40:40+0000");
  script_tag(name:"last_modification", value:"2025-09-05 15:40:40 +0000 (Fri, 05 Sep 2025)");
  script_tag(name:"creation_date", value:"2018-01-04 12:48:23 +0700 (Thu, 04 Jan 2018)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-02-02 18:11:00 +0000 (Fri, 02 Feb 2018)");

  script_cve_id("CVE-2016-10704", "CVE-2018-5301");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Magento XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("sw_magento_detect.nasl");
  script_mandatory_keys("magento/installed");

  script_tag(name:"summary", value:"Magento is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Magento is prone to multiple vulnerabilities:

  - Remote Code Execution in checkout

  - SQL injection in Zend Framework

  - Stored Cross-Site Scripting in email templates

  - Stored XSS in invitations

  - Order item with altered price

  - Guest order view protection code vulnerable to brute-force attack

  - Cross-Site Scripting in section loading

  - Unauthorized removal of customer address

  - Full Page Cache poisoning

  - Information disclosure in maintenance mode

  - Local file inclusion

  - Removal of currently logged-in administrator

  - CSRF delete items from mini cart

  - Session does not expire on logout

  - Admin users can create backups regardless of privileges");

  script_tag(name:"affected", value:"Magento prior to 2.0.10 and 2.1.x.");

  script_tag(name:"solution", value:"Update to version 2.0.10, 2.1.2 or later.");

  script_xref(name:"URL", value:"https://magento.com/security/patches/magento-2010-and-212-security-update");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "2.0.10")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.0.10");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "2.1.0", test_version2: "2.1.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.1.2");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
