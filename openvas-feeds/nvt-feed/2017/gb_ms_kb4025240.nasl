# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811513");
  script_version("2023-07-25T05:05:58+0000");
  script_cve_id("CVE-2017-8592");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-19 22:42:00 +0000 (Wed, 19 Jul 2017)");
  script_tag(name:"creation_date", value:"2017-07-12 09:20:38 +0530 (Wed, 12 Jul 2017)");
  script_name("Microsoft Browser Security Feature Bypass vulnerability (KB4025240)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB4025240");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists when Microsoft Browsers
  improperly handle redirect requests.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  an attacker who successfully exploited this vulnerability to force the
  browser to send data that would otherwise be restricted to a destination web
  site of their choice.");

  script_tag(name:"affected", value:"Microsoft Windows Server 2008 x32/x64 Edition Service Pack 2.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4025240");
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

if(hotfix_check_sp(win2008:3, win2008x64:3) <= 0){
  exit(0);
}

sysPath = smb_get_system32root();
if(!sysPath ){
  exit(0);
}

fileVer = fetch_file_version(sysPath:sysPath, file_name:"msxml3.dll");
if(!fileVer){
  exit(0);
}

if(version_is_less(version:fileVer, test_version:"8.100.5015.0"))
{
  report = 'File checked:     ' + sysPath + "\msxml3.dll" + '\n' +
           'File version:     ' + fileVer  + '\n' +
           'Vulnerable range: ' + 'Less than 8.100.5015.0' + '\n' ;
  security_message(data:report);
  exit(0);
}
exit(0);
