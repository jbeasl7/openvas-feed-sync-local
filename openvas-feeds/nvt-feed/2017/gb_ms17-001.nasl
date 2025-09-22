# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810268");
  script_version("2023-07-14T16:09:27+0000");
  script_cve_id("CVE-2017-0002");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:27 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"creation_date", value:"2017-01-11 08:29:24 +0530 (Wed, 11 Jan 2017)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Edge Privilege Elevation Vulnerability (3214288)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Bulletin MS17-001.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists when Microsoft Edge does
  not properly enforce cross-domain policies with 'about:blank', which could
  allow an attacker to access information from one domain and inject it into
  another domain.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to gain elevated privileges on affected system.");

  script_tag(name:"affected", value:"- Microsoft Windows 10 x32/x64

  - Microsoft Windows Server 2016 x64

  - Microsoft Windows 10 Version 1511 x32/x64

  - Microsoft Windows 10 Version 1607 x32/x64");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3213986");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/95284");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3210721");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3210720");
  script_xref(name:"URL", value:"https://technet.microsoft.com/en-us/library/security/MS17-001");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS17-001");

  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(win10:1, win10x64:1, win2016:1) <= 0){
  exit(0);
}

sysPath = smb_get_system32root();
if(!sysPath ){
  exit(0);
}

edgeVer = fetch_file_version(sysPath:sysPath, file_name:"edgehtml.dll");
if(!edgeVer){
  exit(0);
}

if(hotfix_check_sp(win10:1, win10x64:1, win2016:1) > 0)
{
  if(version_is_less(version:edgeVer, test_version:"11.0.10240.17236"))
  {
    Vulnerable_range = "Less than 11.0.10240.17236";
    VULN = TRUE ;
  }

  else if(version_in_range(version:edgeVer, test_version:"11.0.10586.0", test_version2:"11.0.10586.752"))
  {
    Vulnerable_range = "11.0.10586.0 - 11.0.10586.752";
    VULN = TRUE ;
  }

  else if(version_in_range(version:edgeVer, test_version:"11.0.14393.0", test_version2:"11.0.14393.692"))
  {
    Vulnerable_range = "11.0.14393.0 - 11.0.14393.692";
    VULN = TRUE ;
  }

  if(VULN)
  {
    report = 'File checked:     ' + sysPath + "\edgehtml.dll" + '\n' +
             'File version:     ' + edgeVer  + '\n' +
             'Vulnerable range: ' + Vulnerable_range + '\n' ;
    security_message(data:report);
    exit(0);
  }
}

exit(0);
