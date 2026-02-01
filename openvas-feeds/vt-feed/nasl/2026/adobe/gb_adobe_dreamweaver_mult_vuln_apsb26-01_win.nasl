# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:dreamweaver";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.837036");
  script_version("2026-01-16T05:47:38+0000");
  script_cve_id("CVE-2026-21267", "CVE-2026-21268", "CVE-2026-21274", "CVE-2026-21271",
                "CVE-2026-21272");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2026-01-16 05:47:38 +0000 (Fri, 16 Jan 2026)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-01-13 19:16:24 +0000 (Tue, 13 Jan 2026)");
  script_tag(name:"creation_date", value:"2026-01-14 10:00:09 +0530 (Wed, 14 Jan 2026)");
  script_name("Adobe Dreamweaver Multiple Vulnerabilities (APSB26-01) - Windows");

  script_tag(name:"summary", value:"Adobe Dreamweaver is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to execute arbitrary code.");

  script_tag(name:"affected", value:"Adobe Dreamweaver prior to version 21.7
  on Windows.");

  script_tag(name:"solution", value:"Update to version 21.7 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/dreamweaver/apsb26-01.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone Networks AG");
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

if(version_is_less(version:vers, test_version:"21.7")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"21.7", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);