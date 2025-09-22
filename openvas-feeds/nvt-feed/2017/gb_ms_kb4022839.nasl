# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811208");
  script_version("2025-04-07T05:39:52+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2017-8464", "CVE-2017-8543", "CVE-2017-8552");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-04-07 05:39:52 +0000 (Mon, 07 Apr 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-04-04 20:28:18 +0000 (Fri, 04 Apr 2025)");
  script_tag(name:"creation_date", value:"2017-06-16 16:41:25 +0530 (Fri, 16 Jun 2017)");
  script_name("Microsoft Windows Multiple RCE Vulnerabilities (KB4022839)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft security update KB4022839.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - An error exists in 'Win32k' when the Windows kernel-mode driver fails to
    properly handle objects in memory.

  - An error in the Windows Search which fails to handles objects in memory.

  - An error in .LNK file due to processing of shortcut LNK references.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to run arbitrary code in kernel mode allowing attacker to install programs.
  View, change, or delete data, or create new accounts with full user rights.Also
  an attacker who successfully exploited this vulnerability could run processes
  in an elevated context.");

  script_tag(name:"affected", value:"Microsoft Windows 8 x86/x64.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-ph/help/4022839");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98818");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98824");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99035");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
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

if(hotfix_check_sp(win8:1, win8x64:1) <= 0){
  exit(0);
}

sysPath = smb_get_system32root();
if(!sysPath ){
  exit(0);
}

winVer = fetch_file_version(sysPath:sysPath, file_name:"Shell32.dll");
if(!winVer){
  exit(0);
}

if(version_is_less(version:winVer, test_version:"6.2.9200.22164"))
{
  report = 'File checked:     ' + sysPath + "\Shell32.dll" + '\n' +
           'File version:     ' + winVer  + '\n' +
           'Vulnerable range: ' + 'Less than 6.2.9200.22164' + '\n' ;
  security_message(data:report);
  exit(0);
}
