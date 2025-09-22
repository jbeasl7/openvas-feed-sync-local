# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811864");
  script_version("2023-07-14T16:09:27+0000");
  script_cve_id("CVE-2017-11815", "CVE-2017-11780", "CVE-2017-11781");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:27 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-10-20 13:03:00 +0000 (Fri, 20 Oct 2017)");
  script_tag(name:"creation_date", value:"2017-10-11 09:30:19 +0530 (Wed, 11 Oct 2017)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB4041995)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB4041995");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Windows SMB Server improperly handles certain requests.

  - Microsoft Server Message Block 1 improperly handles certain requests.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  an attacker who exploited this vulnerability to  execute code on the target
  server, cause the affected system to crash and lead to information
  disclosure from the server.");

  script_tag(name:"affected", value:"Microsoft Windows Server 2008 x32/x64 Edition Service Pack 2.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4041995");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101136");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101110");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101140");
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

fileVer = fetch_file_version(sysPath:sysPath, file_name:"drivers\srv.sys");
if(!fileVer){
  exit(0);
}

if(version_is_less(version:fileVer, test_version:"6.0.6002.24201"))
{
  report = 'File checked:     ' + sysPath + "\drivers\srv.sys" + '\n' +
           'File version:     ' + fileVer  + '\n' +
           'Vulnerable range: Less than 6.0.6002.24201\n' ;
  security_message(data:report);
  exit(0);
}
exit(0);
