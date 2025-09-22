# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:edge_chromium_based";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.834964");
  script_version("2025-04-09T05:39:51+0000");
  script_cve_id("CVE-2025-0995", "CVE-2025-0996", "CVE-2025-0997", "CVE-2025-21401");
  script_tag(name:"cvss_base", value:"3.7");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-04-09 05:39:51 +0000 (Wed, 09 Apr 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-02-15 00:15:27 +0000 (Sat, 15 Feb 2025)");
  script_tag(name:"creation_date", value:"2025-02-17 10:26:35 +0530 (Mon, 17 Feb 2025)");
  script_name("Microsoft Edge (Chromium-Based) < 133.0.3065.69 Multiple Vulnerabilities (Feb 2025)");

  script_tag(name:"summary", value:"Microsoft Edge (Chromium-Based) is prone to
  multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"These vulnerabilities exist:

  - CVE-2025-0995: Use after free in V8

  - CVE-2025-0996: Inappropriate implementation in Browser UI

  - CVE-2025-0997: Use after free in Navigation

  - CVE-2025-21401: Microsoft Edge (Chromium-based) Security Feature Bypass Vulnerability

  Note: This advisory initially also contained CVE-2025-0998 but this CVE got rejected in the
  meantime.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to run arbitrary code, privilege escalation, disclose information and conduct
  denial of service attacks.");

  script_tag(name:"affected", value:"Microsoft Edge (Chromium-Based) prior to  version 133.0.3065.69.");

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

if(version_is_less(version:vers, test_version:"133.0.3065.69")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"133.0.3065.69", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
