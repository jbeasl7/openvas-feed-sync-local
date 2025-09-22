# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:edge_chromium_based";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.834448");
  script_version("2025-01-13T08:32:03+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2024-7971", "CVE-2024-41879", "CVE-2024-38207", "CVE-2024-38210",
                "CVE-2024-38209", "CVE-2024-38222");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-01-13 08:32:03 +0000 (Mon, 13 Jan 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-11-27 17:21:35 +0000 (Wed, 27 Nov 2024)");
  script_tag(name:"creation_date", value:"2024-08-27 11:48:12 +0530 (Tue, 27 Aug 2024)");
  script_name("Microsoft Edge (Chromium-Based) Multiple Vulnerabilities (Aug-2 24)");

  script_tag(name:"summary", value:"Microsoft Edge (Chromium-Based) is prone to
  multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"These vulnerabilities exist:

  - CVE-2024-7971: Type confusion in V8

  - CVE-2024-41879: Adobe PDF Viewer Remote Code Execution Vulnerability

  - CVE-2024-38207: Microsoft Edge (HTML-based) Memory Corruption Vulnerability

  - CVE-2024-38210: Microsoft Edge (Chromium-based) Remote Code Execution Vulnerability

  - CVE-2024-38209: Microsoft Edge (Chromium-based) Remote Code Execution Vulnerability

  - CVE-2024-38222: Microsoft Edge (Chromium-based) Information Disclosure Vulnerability");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to run arbitrary code, disclose information and cause denial of service.");

  script_tag(name:"affected", value:"Microsoft Edge (Chromium-Based) prior to  version 128.0.2739.42.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Update to version 128.0.2739.42 or later.");

  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://learn.microsoft.com/en-us/DeployEdge/microsoft-edge-relnotes-security");
  script_xref(name:"URL", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-7971");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
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

if(version_is_less(version:vers, test_version:"128.0.2739.42")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"128.0.2739.42", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
