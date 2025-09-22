# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:dreamweaver";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.836328");
  script_version("2025-05-16T05:40:21+0000");
  script_cve_id("CVE-2025-30310");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-05-16 05:40:21 +0000 (Fri, 16 May 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-05-13 17:15:59 +0000 (Tue, 13 May 2025)");
  script_tag(name:"creation_date", value:"2025-05-15 14:59:06 +0530 (Thu, 15 May 2025)");
  script_name("Adobe Dreamweaver Arbitrary Code Vulnerability (APSB25-35) - Windows");

  script_tag(name:"summary", value:"Adobe Dreamweaver is prone to an arbitrary
  code vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to execute arbitrary code.");

  script_tag(name:"affected", value:"Adobe Dreamweaver prior to version 21.5
  on Windows.");

  script_tag(name:"solution", value:"Update to version 21.5 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/dreamweaver/apsb25-35.html");
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

if(version_is_less(version:vers, test_version:"21.5")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"21.5", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);