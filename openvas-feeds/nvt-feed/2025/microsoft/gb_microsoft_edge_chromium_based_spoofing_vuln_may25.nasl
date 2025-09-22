# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:edge_chromium_based";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.836185");
  script_version("2025-05-06T05:40:10+0000");
  script_cve_id("CVE-2025-29825");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-05-06 05:40:10 +0000 (Tue, 06 May 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-05-02 02:15:16 +0000 (Fri, 02 May 2025)");
  script_tag(name:"creation_date", value:"2025-05-02 10:00:14 +0530 (Fri, 02 May 2025)");
  script_name("Microsoft Edge (Chromium-Based) Spoofing Vulnerability (May 2025)");

  script_tag(name:"summary", value:"Microsoft Edge (Chromium-Based) is prone to
  a spoofing vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to a Spoofing
  vulnerability in Microsoft Edge (Chromium-based).");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to conduct spoofing attack.");

  script_tag(name:"affected", value:"Microsoft Edge (Chromium-Based) prior to version 136.0.3240.50.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"The vendor has released updates. Please
  see the references for more information.");

  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-29825");
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

if(version_is_less(version:vers, test_version:"136.0.3240.50")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"136.0.3240.50", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);