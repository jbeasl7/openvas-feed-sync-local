# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:edge_chromium_based";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.826574");
  script_version("2025-09-12T05:38:45+0000");
  script_cve_id("CVE-2022-3373", "CVE-2022-3370", "CVE-2022-3317", "CVE-2022-3316",
                "CVE-2022-3315", "CVE-2022-3313", "CVE-2022-3311", "CVE-2022-3310",
                "CVE-2022-3308", "CVE-2022-3307", "CVE-2022-3304", "CVE-2022-41035");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-09-12 05:38:45 +0000 (Fri, 12 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-11-01 22:15:00 +0000 (Tue, 01 Nov 2022)");
  script_tag(name:"creation_date", value:"2022-10-12 10:42:18 +0530 (Wed, 12 Oct 2022)");
  script_name("Microsoft Edge (Chromium-Based) Multiple Vulnerabilities (Oct 2022)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Edge (Chromium-Based) update.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Out of bounds write in V8.

  - Insufficient validation of untrusted input in Intents.

  For more information about the vulnerabilities refer to Reference links.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to bypass security restrictions on affected system.");

  script_tag(name:"affected", value:"Microsoft Edge (Chromium-Based) prior to version 106.0.1370.34.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/deployedge/microsoft-edge-relnotes-security");
  script_xref(name:"URL", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-41035");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_microsoft_edge_chromium_based_detect_win.nasl");
  script_mandatory_keys("microsoft_edge_chromium/installed", "microsoft_edge_chromium/ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"106.0.1370.34")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"106.0.1370.34", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
