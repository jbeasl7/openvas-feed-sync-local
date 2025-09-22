# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:magentocommerce:magento";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142211");
  script_version("2024-02-19T05:05:57+0000");
  script_tag(name:"last_modification", value:"2024-02-19 05:05:57 +0000 (Mon, 19 Feb 2024)");
  script_tag(name:"creation_date", value:"2019-03-29 09:22:59 +0000 (Fri, 29 Mar 2019)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");

  script_cve_id("CVE-2019-8235");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Magento 2.x Multiple Vulnerabilities (Mar 2019)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("sw_magento_detect.nasl");
  script_mandatory_keys("magento/installed");

  script_tag(name:"summary", value:"Magento 2.x is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Magento 2.x is prone to multiple vulnerabilities:

  - Remote code execution though crafted newsletter and email templates

  - Remote code execution through email template

  - SQL Injection and cross-site scripting vulnerability in Catalog section (XSS)

  - SQL Injection vulnerability through an unauthenticated user

  - Arbitrary code execution due to unsafe deserialization of a PHP archive

  - Arbitrary code execution due to the unsafe handling of an API call to a core bundled extension

  - Arbitrary code execution due to unsafe deserialization of a PHP Archive

  - Sensitive data disclosure due to NGINX configuration's regular expressions not being restricted to the
    explicit directories

  - Cross Site Scripting in newsletter template name

  - Stored cross-site scripting in the Admin Customer Segments area

  - Unauthorized implementation due to bypassing the need for administrator authentication approval on B2B accounts

  - Unauthorized data control due to a bypass of authentication controls for a customer using a web API endpoint

  - SQL injection due to inadequate validation of user input

  - Reflected cross-site scripting vulnerability in the Admin through the requisition list ID

  - Stored cross-site scripting in the admin panel via the Admin Shopping Cart Rules page

  - Deletion of a product attribute through cross-site request forgery

  - Site map deletion through cross-site request forgery

  - Deletion of synonym groups through a cross-site request forgery vulnerability

  - Stored cross-site scripting in the admin panel via the Terms & Conditions with Checkbox Text field in the
    admin panel.

  - Stored cross-site scripting in the Admin through the Admin Notification function

  - Stored cross-site scripting vulnerability in Admin product names

  - Stored cross-site scripting in the Admin through B2B packages

  - Stored cross-site scripting vulnerability

  - Stored cross-site scripting vulnerability in the Admin through the Checkbox Custom Option Value field

  - Stored cross-site scripting vulnerability in the Admin through B2B packages

  - Stored cross-site scripting in the admin panel via the Attribute Label for Media Attributes section

  - Reflected cross-site scripting through manipulation of the Admin notification feed URL

  - Stored cross-site scripting in the Admin Catalog configuration section

  - Stored cross-site scripting in the Admin panel through the product configurations section

  - WYSIWYG

  - Missing CAPTCHA on Send to a friend page

  - Information disclosure in Magento 2.x default configuration

  - Sensitive Data Disclosure due toInsecure Direct Object References vulnerability

  - Spam using share a wishlist functionality

  - Admin credentials are logged in exception reports

  - Unauthorized access to wishlist via Insecure direct object reference in the application

  - HTML injection vulnerability due to insufficient data validation");

  script_tag(name:"solution", value:"Update to version 2.1.17, 2.2.8, 2.3.1 or later.");

  script_xref(name:"URL", value:"https://magento.com/security/patches/magento-2.3.1-2.2.8-and-2.1.17-security-update");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
path = infos["location"];

if (version_in_range(version: version, test_version: "2.0", test_version2: "2.1.16")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.1.17", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "2.2", test_version2: "2.2.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.2.8", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

if (version_is_equal(version: version, test_version: "2.3.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.3.1", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
