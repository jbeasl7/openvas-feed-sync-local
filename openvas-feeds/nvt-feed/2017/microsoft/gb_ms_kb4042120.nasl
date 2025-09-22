# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811920");
  script_version("2023-07-14T16:09:27+0000");
  script_cve_id("CVE-2017-8694", "CVE-2017-11765", "CVE-2017-11814", "CVE-2017-11824",
                "CVE-2017-8689");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:27 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"creation_date", value:"2017-10-11 08:44:10 +0530 (Wed, 11 Oct 2017)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB4042120)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB4042120");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - The Windows kernel improperly handles objects in memory.

  - The Windows kernel-mode driver fails to properly handle objects in memory.

  - The Windows Graphics Component improperly handles objects in memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to obtain information to further compromise the user's system and also run
  arbitrary code in kernel mode.");

  script_tag(name:"affected", value:"Microsoft Windows Server 2008 x32/x64 Edition Service Pack 2.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4042120");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101100");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101111");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101093");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101099");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101128");
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

if(version_is_less(version:fileVer, test_version:"6.0.6002.24200"))
{
  report = 'File checked:     ' + sysPath + "\win32k.sys" + '\n' +
           'File version:     ' + fileVer  + '\n' +
           'Vulnerable range: Less than 6.0.6002.24200\n' ;
  security_message(data:report);
  exit(0);
}
exit(0);
