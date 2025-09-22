# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:magentocommerce:magento";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142212");
  script_version("2024-06-26T05:05:39+0000");
  script_tag(name:"last_modification", value:"2024-06-26 05:05:39 +0000 (Wed, 26 Jun 2024)");
  script_tag(name:"creation_date", value:"2019-03-29 10:17:27 +0000 (Fri, 29 Mar 2019)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_name("Magento 1.x Multiple Vulnerabilities (SUPEE-11086)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("sw_magento_detect.nasl");
  script_mandatory_keys("magento/installed");

  script_xref(name:"URL", value:"https://magento.com/security/patches/supee-11086");

  script_tag(name:"summary", value:"Magento 1.x is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - SQL Injection vulnerability through an unauthenticated user

  - Remote code execution via server side request forgery issued to Redis

  - Arbitrary code execution due to unsafe handling of a malicious product attribute configuration

  - Arbitrary code execution due to unsafe deserialization of a PHP archive

  - Arbitrary code execution due to unsafe handling of a malicious layout update

  - Remote code execution through PHP code that can be uploaded to the nginx server due to crafted
  customer store attributes

  - Remote code execution through arbitrary XML data sent through a layout table

  - Arbitrary code execution through bypass of PHP file upload restriction

  - Arbitrary code execution due to bypass of layout validator

  - Stored cross-site scripting in the escaper framework

  - Reflected cross-site scriptingin the product widget chooser section of the Admin

  - Deletion of Catalog rules through cross-site request forgery

  - Deletion of Catalog products through cross-site request forgery

  - Stored cross-site scripting in the admin panel via the Admin Shopping Cart Rules page

  - Deletion of SOAP/XML-RPC-User and SOAP/XML-RPC-Role through cross-site request forgery

  - Deletion of user roles through cross-site request forgery

  - Deletion of store design schedule through cross-site request forgery

  - Deletion of shopping cart price rules through cross-site request forgery

  - Deletion of REST-Role and REST-OAuth Consumer, and change of REST-Attribute via cross-site
  request forgery

  - Deletion of a product attribute through cross-site request forgery

  - Deletion of an Admin user through cross-site request forgery

  - Stored cross-site scripting in the Admin through the Email Template Preview section

  - Data manipulation due to improper validation

  - Admin credentials are logged in exception reports

  - Unauthorized access to the order list through an insecure direct object reference in the
  application");

  script_tag(name:"solution", value:"Update to version 1.9.4.1 (CE), 1.14.4.1 (EE) or later.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

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

# nb: Don't exit if empty as we always want to fallback to the CE check below if no edition could be
# gathered in the detection VT.
edition = get_kb_item("magento/edition/" + port + "/" + location);

if (edition == "EE") {
  if (version_in_range(version: version, test_version: "1.9.0.0", test_version2: "1.14.4.0")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "1.14.4.1", install_path: location);
    security_message(port: port, data: report);
    exit(0);
  }
} else {
  if (version_in_range(version: version, test_version: "1.5.0.0", test_version2: "1.9.4.0")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "1.9.4.1", install_path: location);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
