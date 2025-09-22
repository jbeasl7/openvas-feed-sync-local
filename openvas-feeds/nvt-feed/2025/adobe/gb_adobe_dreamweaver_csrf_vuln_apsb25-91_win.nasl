# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:dreamweaver";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.836653");
  script_version("2025-09-12T15:39:53+0000");
  script_cve_id("CVE-2025-54256");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-09-12 15:39:53 +0000 (Fri, 12 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-09-09 19:15:51 +0000 (Tue, 09 Sep 2025)");
  script_tag(name:"creation_date", value:"2025-09-11 11:05:08 +0530 (Thu, 11 Sep 2025)");
  script_name("Adobe Dreamweaver CSRF Vulnerability (APSB25-91) - Windows");

  script_tag(name:"summary", value:"Adobe Dreamweaver is prone to a cross-site request forgery
  (CSRF) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to execute arbitrary code.");

  script_tag(name:"affected", value:"Adobe Dreamweaver prior to version 21.6
  on Windows.");

  script_tag(name:"solution", value:"Update to version 21.6 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/dreamweaver/apsb25-91.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone Networks AG");
  script_family("Privilege escalation");
  script_dependencies("secpod_adobe_dreamweaver_detect.nasl");
  script_mandatory_keys("Adobe/Dreamweaver/Ver");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"21.6")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"21.6", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);