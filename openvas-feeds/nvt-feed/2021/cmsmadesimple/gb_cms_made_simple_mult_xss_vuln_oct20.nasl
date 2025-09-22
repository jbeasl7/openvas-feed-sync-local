# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cmsmadesimple:cms_made_simple";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.146258");
  script_version("2025-01-21T05:37:33+0000");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2021-07-12 09:23:42 +0000 (Mon, 12 Jul 2021)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-06 12:09:00 +0000 (Tue, 06 Jul 2021)");

  script_cve_id("CVE-2020-36408", "CVE-2020-36409", "CVE-2020-36410", "CVE-2020-36411", "CVE-2020-36412",
                "CVE-2020-36413", "CVE-2020-36414", "CVE-2020-36415", "CVE-2020-36416");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("CMS Made Simple < 2.2.15 Multiple XSS Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_cms_made_simple_http_detect.nasl");
  script_mandatory_keys("cmsmadesimple/detected");

  script_tag(name:"summary", value:"CMS Made Simple is prone to multiple cross-site scripting
  (XSS) vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2020-36408: XSS in the 'Add Shortcut' parameter under the 'Manage Shortcuts' module

  - CVE-2020-36409: XSS in the 'Add Category' parameter under the 'Categories' module

  - CVE-2020-36410: XSS in the 'Email address to receive notification of news submission' parameter
  under the 'Options' module

  - CVE-2020-36411: XSS in the 'Path for the {page_image} tag:' or 'Path for thumbnail field:'
  parameters under the 'Content Editing Settings' module

  - CVE-2020-36412: XSS in the 'Search Text' field under the 'Admin Search' module

  - CVE-2020-36413: XSS in the 'Exclude these IP addresses from the 'Site Down' status' parameter
  under the 'Maintenance Mode' module

  - CVE-2020-36414: XSS in the 'Extra' fields under the 'Add Article' feature

  - CVE-2020-36415: XSS in the 'Create a new Stylesheet' parameter under the 'Stylesheets' module

  - CVE-2020-36416: XSS in the 'Create a new Design' parameter under the 'Designs' module");

  script_tag(name:"impact", value:"Successful exploitation would allow an authenticated
  attacker to inject arbitrary HTML and JavaScript into the site.");

  script_tag(name:"affected", value:"CMS Made Simple through version 2.2.14.");

  script_tag(name:"solution", value:"Update to version 2.2.15 or later.");

  script_xref(name:"URL", value:"http://dev.cmsmadesimple.org/bug/view/12325");

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

if (version_is_less(version: version, test_version: "2.2.15")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.2.15", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
