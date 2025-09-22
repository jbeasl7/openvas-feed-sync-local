# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:zope:zope";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.146437");
  script_version("2023-10-06T05:06:29+0000");
  script_tag(name:"last_modification", value:"2023-10-06 05:06:29 +0000 (Fri, 06 Oct 2023)");
  script_tag(name:"creation_date", value:"2021-08-04 09:22:51 +0000 (Wed, 04 Aug 2021)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-08-11 15:25:00 +0000 (Wed, 11 Aug 2021)");

  script_cve_id("CVE-2021-32811");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Zope RCE Vulnerability (GHSA-g4gq-j4p2-j8fr)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_zope_http_detect.nasl");
  script_mandatory_keys("zope/detected");

  script_tag(name:"summary", value:"Zope is prone to a remote code execution (RCE) vulnerability
  via Script (Python) objects under Python 3.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The optional add-on package Products.PythonScripts adds Script
  (Python) to the list of content items a user can add to the Zope object database. Inside these
  scripts users can write Python code that is executed when rendered through the web. The code
  environment in these script objects is limited, it relies on the RestrictedPython package to
  provide a 'safe' subset of Python instructions as well as the AccessControl package that defines
  security policies for execution in the context of a Zope application.

  Recently the AccessControl package was updated to fix a remote code execution security issue. The
  bug tightens the AccessControl security policies for Zope by blocking access to unsafe classes
  inside the Python string module.

  You are only affected if the following are true:

  - You use Python 3 for your Zope deployment (Zope 4 on Python 2 is not affected)

  - You run Zope 4 below version 4.6.3 or Zope 5 below version 5.3

  - You have installed the optional Products.PythonScripts add-on package

  By default, you need to have the admin-level Zope 'Manager' role to add or edit Script (Python)
  objects through the web. Only sites that allow untrusted users to add/edit these scripts through
  the web are at risk.");

  script_tag(name:"affected", value:"Zope version 4.0 through 4.6.2 and 5.0 through 5.2.");

  script_tag(name:"solution", value:"Update to version 4.6.3, 5.3 or later.");

  script_xref(name:"URL", value:"https://github.com/zopefoundation/Zope/security/advisories/GHSA-g4gq-j4p2-j8fr");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range(version: version, test_version: "4.0", test_version2: "4.6.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.6.3");
  security_message(port: port, data: report);
  exit(0);
}

if (version =~ "^5\." && version_is_less(version: version, test_version: "5.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.3");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
