# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811673");
  script_version("2023-07-14T16:09:27+0000");
  script_cve_id("CVE-2017-8675", "CVE-2017-8676", "CVE-2017-8720", "CVE-2017-8678",
                "CVE-2017-8680", "CVE-2017-8681", "CVE-2017-8682", "CVE-2017-8683",
                "CVE-2017-8684", "CVE-2017-8685", "CVE-2017-8687", "CVE-2017-8688",
                "CVE-2017-8695", "CVE-2017-8696");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:27 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-05-10 19:58:00 +0000 (Fri, 10 May 2019)");
  script_tag(name:"creation_date", value:"2017-09-13 09:37:18 +0530 (Wed, 13 Sep 2017)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB4039384)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB4039384");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - The way Windows Uniscribe handles objects in memory.

  - The Windows kernel improperly handles objects in memory.

  - When Windows Uniscribe improperly discloses the contents of its memory.

  - When the Windows GDI+ component improperly discloses kernel memory addresses.

  - When the Microsoft Windows Graphics Component improperly handles objects in
    memory.

  - When the Windows font library improperly handles specially crafted embedded
    fonts.

  - The way that the Windows Graphics Device Interface (GDI) handles objects in
    memory, allowing an attacker to retrieve information from a targeted system.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to take control of the affected system and obtain access to information to further
  compromise the user's system.");

  script_tag(name:"affected", value:"Microsoft Windows Server 2008 x32/x64 Edition Service Pack 2.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4039384");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100752");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100755");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100769");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100722");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100727");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100772");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100781");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100782");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100724");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100736");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100756");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100773");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100780");
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

if(version_is_less(version:fileVer, test_version:"6.0.6002.19862"))
{
  Vulnerable_range = "Less than 6.0.6002.19862";
  VULN = TRUE ;
}

else if(version_in_range(version:fileVer, test_version:"6.0.6002.23000", test_version2:"6.0.6002.24182"))
{
  Vulnerable_range = "6.0.6002.23000 - 6.0.6002.24182";
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
