# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814616");
  script_version("2023-07-20T05:05:18+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2018-8477", "CVE-2018-8514", "CVE-2018-8611", "CVE-2018-8619",
                "CVE-2018-8622", "CVE-2018-8625", "CVE-2018-8626", "CVE-2018-8631",
                "CVE-2018-8639", "CVE-2018-8641", "CVE-2018-8643", "CVE-2018-8595",
                "CVE-2018-8596");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:18 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2018-12-12 13:11:27 +0530 (Wed, 12 Dec 2018)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB4471320)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB4471320");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Windows kernel fails to properly handle objects in memory.

  - Internet Explorer VBScript execution policy does not properly
    restrict VBScript under specific conditions.

  - Scripting engine improperly handles objects in memory in Internet
    Explorer.

  - Windows kernel-mode driver fails to properly handle objects in memory.

  - Internet Explorer improperly accesses objects in memory

  - Windows GDI component improperly discloses the contents of its
    memory.

  - Windows Domain Name System (DNS) servers when they fail to properly handle
    requests.

  - Windows Win32k component fails to properly handle objects in memory.

  - VBScript engine improperly handles objects in memory.

  - Remote Procedure Call runtime improperly initializes objects in memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to run arbitrary code, elevate privileges and obtain information to further
  compromise the user's system.");

  script_tag(name:"affected", value:"- Microsoft Windows 8.1 for 32-bit/x64

  - Microsoft Windows Server 2012 R2");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4471320");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(win8_1:1, win8_1x64:1, win2012R2:1) <= 0){
  exit(0);
}

sysPath = smb_get_system32root();
if(!sysPath ){
  exit(0);
}

fileVer = fetch_file_version(sysPath:sysPath, file_name:"win32k.sys");
if(!fileVer){
  exit(0);
}

if(version_is_less(version:fileVer, test_version:"6.3.9600.19208"))
{
  report = report_fixed_ver(file_checked:sysPath + "\win32k.sys",
                            file_version:fileVer, vulnerable_range:"Less than 6.3.9600.19208");
  security_message(data:report);
  exit(0);
}
exit(99);
