# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:edge_chromium_based";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.834900");
  script_version("2025-01-24T05:37:33+0000");
  script_cve_id("CVE-2024-7970", "CVE-2024-8362");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-01-24 05:37:33 +0000 (Fri, 24 Jan 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-01-02 17:37:05 +0000 (Thu, 02 Jan 2025)");
  script_tag(name:"creation_date", value:"2025-01-21 15:51:44 +0530 (Tue, 21 Jan 2025)");
  script_name("Microsoft Edge (Chromium-Based) < 128.0.2739.63 Multiple Vulnerabilities (Jan 2025)");

  script_tag(name:"summary", value:"Microsoft Edge (Chromium-Based) is prone to
  multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"These vulnerabilities exist:

  - CVE-2024-7970: Out of bounds write in V8

  - CVE-2024-8362: Use after free in WebAudio");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to run arbitrary code and conduct denial of service attacks.");

  script_tag(name:"affected", value:"Microsoft Edge (Chromium-Based) prior to  version 128.0.2739.63.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"The vendor has released updates. Please
  see the references for more information.");

  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://learn.microsoft.com/en-us/DeployEdge/microsoft-edge-relnotes-security");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
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

if(version_is_less(version:vers, test_version:"128.0.2739.63")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"128.0.2739.63", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
