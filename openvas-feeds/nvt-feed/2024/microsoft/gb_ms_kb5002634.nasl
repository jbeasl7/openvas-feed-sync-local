# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.834491");
  script_version("2024-09-18T07:47:18+0000");
  script_cve_id("CVE-2024-43463");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-09-18 07:47:18 +0000 (Wed, 18 Sep 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-09-10 17:15:33 +0000 (Tue, 10 Sep 2024)");
  script_tag(name:"creation_date", value:"2024-09-11 16:23:06 +0530 (Wed, 11 Sep 2024)");
  script_name("Microsoft Visio 2016 RCE Vulnerability (KB5002634)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB5002634");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to a remote code
  execution vulnerability in Microsoft Office Visio.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to conduct remote code execution on an affected system.");

  script_tag(name:"affected", value:"Microsoft Visio 2016.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/5002634");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");
  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

sysPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\visio.exe", item:"Path");
if(!sysPath)
  exit(0);

version = fetch_file_version(sysPath:sysPath, file_name:"visio.exe");
if(!version)
  exit(0);

if(version_in_range(version:version, test_version:"16.0", test_version2:"16.0.5465.0999")) {
  report = report_fixed_ver(file_checked:"visio.exe", file_version:version, vulnerable_range:"16.0 - 16.0.5465.0999");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
