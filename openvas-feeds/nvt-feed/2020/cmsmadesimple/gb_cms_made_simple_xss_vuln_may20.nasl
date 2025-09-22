# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cmsmadesimple:cms_made_simple";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.144021");
  script_version("2025-01-21T05:37:33+0000");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2020-06-03 03:39:07 +0000 (Wed, 03 Jun 2020)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-09-28 21:17:00 +0000 (Tue, 28 Sep 2021)");

  script_cve_id("CVE-2020-13660", "CVE-2020-27377", "CVE-2020-23481");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("CMS Made Simple <= 2.2.14 Multiple XSS Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_cms_made_simple_http_detect.nasl");
  script_mandatory_keys("cmsmadesimple/detected");

  script_tag(name:"summary", value:"CMS Made Simple is prone to multiple cross-site scripting (XSS)
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2020-13660: XSS via a crafted File Picker profile name

  - CVE-2020-27377: XSS in the Administrator panel on the 'Setting News' module

  - CVE-2020-23481: XSS in the Field Definition text field");

  script_tag(name:"affected", value:"CMS Made Simple version 2.2.14 and prior.");

  script_tag(name:"solution", value:"Update to version 2.2.15 or later.");

  script_xref(name:"URL", value:"http://dev.cmsmadesimple.org/bug/view/12312");
  script_xref(name:"URL", value:"http://dev.cmsmadesimple.org/bug/view/12317");

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

if (version_is_less_equal(version: version, test_version: "2.2.14")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.2.15", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
