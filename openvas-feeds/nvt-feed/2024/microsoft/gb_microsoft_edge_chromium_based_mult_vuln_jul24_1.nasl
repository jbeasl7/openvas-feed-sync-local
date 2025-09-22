# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:edge_chromium_based";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.834277");
  script_version("2024-08-08T05:05:42+0000");
  script_cve_id("CVE-2024-7000", "CVE-2024-6999", "CVE-2024-7004", "CVE-2024-6996",
                "CVE-2024-7001", "CVE-2024-7005", "CVE-2024-6994", "CVE-2024-6988",
                "CVE-2024-6989", "CVE-2024-6991", "CVE-2024-6997", "CVE-2024-6998",
                "CVE-2024-6993", "CVE-2024-6995", "CVE-2024-38103", "CVE-2024-39379",
                "CVE-2024-7003", "CVE-2024-6992");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-08-08 05:05:42 +0000 (Thu, 08 Aug 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-08-07 13:35:02 +0000 (Wed, 07 Aug 2024)");
  script_tag(name:"creation_date", value:"2024-07-29 10:41:53 +0530 (Mon, 29 Jul 2024)");
  script_name("Microsoft Edge (Chromium-Based) Multiple Vulnerabilities (Jul-1 24)");

  script_tag(name:"summary", value:"Microsoft Edge (Chromium-Based) is prone to
  multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"These vulnerabilities exist:

  - CVE-2024-38103: Microsoft Edge (Chromium-based) Information Disclosure Vulnerability

  - CVE-2024-39379: Microsoft Edge (Chromium-based) Remote Code Execution Vulnerability

  - CVE-2024-7003: Inappropriate implementation in FedCM");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to run arbitrary code, bypass security restrictions, disclose information,
  conduct spoofing and cause denial of service.");

  script_tag(name:"affected", value:"Microsoft Edge (Chromium-Based) prior to  version 127.0.2651.74.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"The vendor has released updates. Please
  see the references for more information.");

  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://learn.microsoft.com/en-us/DeployEdge/microsoft-edge-relnotes-security");
  script_xref(name:"URL", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-38103");
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

if(version_is_less(version:vers, test_version:"127.0.2651.74")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"127.0.2651.74", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
