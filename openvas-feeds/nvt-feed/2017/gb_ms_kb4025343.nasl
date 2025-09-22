# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811464");
  script_version("2023-07-25T05:05:58+0000");
  script_cve_id("CVE-2017-0170", "CVE-2017-8463", "CVE-2017-8467", "CVE-2017-8486",
                "CVE-2017-8495", "CVE-2017-8556", "CVE-2017-8557", "CVE-2017-8561",
                "CVE-2017-8562", "CVE-2017-8563", "CVE-2017-8564", "CVE-2017-8565",
                "CVE-2017-8573", "CVE-2017-8577", "CVE-2017-8578", "CVE-2017-8580",
                "CVE-2017-8581", "CVE-2017-8582", "CVE-2017-8587", "CVE-2017-8588",
                "CVE-2017-8589", "CVE-2017-8590", "CVE-2017-8592");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"creation_date", value:"2017-07-12 09:58:32 +0530 (Wed, 12 Jul 2017)");
  script_name("Microsoft Windows Server 2012 Multiple Vulnerabilities (KB4025343)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB4025343");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - When Win32k fails to properly handle objects in memory.

  - When the Microsoft Graphics Component fails to properly handle
    objects in memory.

  - When Windows Explorer improperly handles executable files and shares during
    rename operations.

  - When Windows improperly handles calls to Advanced Local Procedure Call (ALPC).

  - The way that the Windows Kernel handles objects in memory.

  - The way that Microsoft WordPad parses specially crafted files.

  - when Windows Explorer attempts to open a non-existent file.

  - when Windows improperly handles objects in memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  who successfully exploited the vulnerability could gain the same user rights as
  the current user, could run arbitrary code, processes with elevated privileges.
  Also could take control of the affected system and cause a denial of service.");

  script_tag(name:"affected", value:"Microsoft Windows Server 2012.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4025343");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99389");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99409");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99414");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99424");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99439");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99398");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99426");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99397");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99402");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99428");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99394");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99431");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99416");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99419");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99421");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99423");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99429");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99413");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99400");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99425");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99427");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99396");
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

if(hotfix_check_sp(win2012:1) <= 0){
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

if(version_is_less(version:fileVer, test_version:"6.2.9200.22210"))
{
  report = 'File checked:     ' + sysPath + "\win32k.sys" + '\n' +
           'File version:     ' + fileVer  + '\n' +
           'Vulnerable range:  Less than 6.2.9200.22210\n' ;
  security_message(data:report);
  exit(0);
}
exit(0);
