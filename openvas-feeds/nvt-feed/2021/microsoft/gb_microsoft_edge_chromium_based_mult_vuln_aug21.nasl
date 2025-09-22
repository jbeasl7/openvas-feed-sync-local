# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:edge_chromium_based";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.818180");
  script_version("2025-09-12T05:38:45+0000");
  script_cve_id("CVE-2021-30590", "CVE-2021-30591", "CVE-2021-30592", "CVE-2021-30593",
                "CVE-2021-30594", "CVE-2021-30596", "CVE-2021-30597");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-09-12 05:38:45 +0000 (Fri, 12 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-08-27 17:50:00 +0000 (Fri, 27 Aug 2021)");
  script_tag(name:"creation_date", value:"2021-08-11 17:35:18 +0530 (Wed, 11 Aug 2021)");
  script_name("Microsoft Edge (Chromium-Based) Multiple Vulnerabilities (Aug 2021)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Edge (Chromium-Based) updates.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - An use after free error in Page Info UI.

  - An out of bounds read in Tab Strip.

  - An out of bounds write in Tab Groups.

  - An use after free in File System API.

  - A heap buffer overflow in Bookmarks.

  - An use after free error in Browser UI.

  - An incorrect security UI in Navigation.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to execute arbitrary code, gain access to sensitive information and conduct
  spoofing atatck on an affected system.");

  script_tag(name:"affected", value:"Microsoft Edge (Chromium-Based) prior to version 92.0.902.67.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/DeployEdge/microsoft-edge-relnotes-security");
  script_xref(name:"URL", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-30591");
  script_xref(name:"URL", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-30593");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
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

if(version_is_less(version:vers, test_version:"92.0.902.67")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"92.0.902.67", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
