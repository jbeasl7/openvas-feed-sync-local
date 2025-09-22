# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:edge_chromium_based";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832029");
  script_version("2025-09-12T05:38:45+0000");
  script_cve_id("CVE-2023-1213", "CVE-2023-1214", "CVE-2023-1215", "CVE-2023-1216",
                "CVE-2023-1217", "CVE-2023-1218", "CVE-2023-1219", "CVE-2023-1220",
                "CVE-2023-1221", "CVE-2023-1222", "CVE-2023-1223", "CVE-2023-1224",
                "CVE-2023-1228", "CVE-2023-1229", "CVE-2023-1230", "CVE-2023-1231",
                "CVE-2023-1232", "CVE-2023-1234", "CVE-2023-1235", "CVE-2023-24892",
                "CVE-2023-1233", "CVE-2023-1236");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-09-12 05:38:45 +0000 (Fri, 12 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-03-11 02:38:00 +0000 (Sat, 11 Mar 2023)");
  script_tag(name:"creation_date", value:"2023-03-15 09:32:56 +0530 (Wed, 15 Mar 2023)");
  script_name("Microsoft Edge (Chromium-Based) Multiple Vulnerabilities (Mar 2023)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Edge (Chromium-Based) updates.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - Multiple Heap buffer overflow vulnerabilities.

  - A spoofing vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to cause heap buffer overflow and conduct spoofing attack.");

  script_tag(name:"affected", value:"Microsoft Edge (Chromium-Based) prior to version 111.0.1661.41.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://learn.microsoft.com/en-us/DeployEdge/microsoft-edge-relnotes-security");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
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

if(version_is_less(version:vers, test_version:"111.0.1661.41")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"111.0.1661.41", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
