# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811224");
  script_version("2023-07-14T16:09:27+0000");
  script_cve_id("CVE-2017-8467", "CVE-2017-8486", "CVE-2017-8556", "CVE-2017-8573",
                "CVE-2017-8577", "CVE-2017-8578", "CVE-2017-8580", "CVE-2017-8581");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:27 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"creation_date", value:"2017-07-12 09:05:15 +0530 (Wed, 12 Jul 2017)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB4025877)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB4025877");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Microsoft Windows fails to properly handle objects in memory.

  - Microsoft Windows Graphics Component fails to properly handle objects in
    memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to obtain access to sensitive information to further compromise the user's
  system, run arbitrary code in kernel mode and run processes in an elevated
  context.");

  script_tag(name:"affected", value:"Microsoft Windows Server 2008 x32/x64 Edition Service Pack 2.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4025877");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99409");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99414");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99439");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99431");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99416");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99419");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99421");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99423");
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

if(hotfix_check_sp(win2008:3, win2008x64:3) <= 0){
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

if(version_is_less(version:fileVer, test_version:"6.0.6002.19816"))
{
  Vulnerable_range = "Less than 6.0.6002.19816";
  VULN = TRUE ;
}

else if(version_in_range(version:fileVer, test_version:"6.0.6002.23000", test_version2:"6.0.6002.24135"))
{
  Vulnerable_range = "6.0.6002.23000 - 6.0.6002.24135";
  VULN = TRUE ;
}

if(VULN)
{
  report = 'File checked:     ' + sysPath + "\win32k.sys" + '\n' +
           'File version:     ' + fileVer  + '\n' +
           'Vulnerable range: ' + Vulnerable_range + '\n' ;
  security_message(data:report);
  exit(0);
}
exit(0);
