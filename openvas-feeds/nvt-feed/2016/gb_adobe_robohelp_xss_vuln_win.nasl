# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:robohelp";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809840");
  script_version("2023-11-24T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-11-24 05:05:36 +0000 (Fri, 24 Nov 2023)");
  script_tag(name:"creation_date", value:"2016-12-15 16:08:47 +0530 (Thu, 15 Dec 2016)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-07 16:08:00 +0000 (Thu, 07 Mar 2019)");

  script_cve_id("CVE-2016-7891");

  script_tag(name:"qod_type", value:"registry");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Adobe RoboHelp XSS Vulnerability (APSB16-46)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("General");
  script_dependencies("gb_adobe_robohelp_nd_robohelp_server_smb_login_detect.nasl");
  script_mandatory_keys("adobe/robohelp/detected");

  script_tag(name:"summary", value:"Adobe RoboHelp is prone to a cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an improper sanitization of user-supplied
  input.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary
  script code in the context of the affected website. This may allow the attacker to steal
  cookie-based authentication credentials and to launch other attacks.");

  script_tag(name:"affected", value:"Adobe RoboHelp version 11 and prior and 2015.x through 2015.0.3.");

  script_tag(name:"solution", value:"- Version 11 and prior: Apply the hotfix from the referenced
  advisory. Note: Please create an override for this result if the hotfix has been already applied.

  - Version 2015: Update to version 2015.0.4 or later");

  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/robohelp/apsb16-46.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/94878");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!infos = get_app_version_and_location(cpe: CPE, exit_no_version: TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if (version_is_less_equal(version: vers, test_version: "11.0")) {
  report = report_fixed_ver(installed_version: vers, fixed_version: "See advisory", install_path: path);
  security_message(port: 0, data: report);
  exit(0);
}

# nb: Seems version 2015 was the first one using four digits
if (version_in_range_exclusive(version: vers, test_version_lo: "2015.0", test_version_up: "2015.0.4")) {
  report = report_fixed_ver(installed_version: vers, fixed_version: "2015.0.4", install_path: path);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
