# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808161");
  script_version("2023-07-20T05:05:17+0000");
  script_cve_id("CVE-2016-3227");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-05-08 22:03:00 +0000 (Wed, 08 May 2019)");
  script_tag(name:"creation_date", value:"2016-06-15 08:10:05 +0530 (Wed, 15 Jun 2016)");
  script_name("Microsoft Windows DNS Server Remote Code Execution Vulnerability (3164065)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft Bulletin MS16-071");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to improper handling of requests
  in DNS severs.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attacker to run arbitrary code in the context of the Local System Account.");

  script_tag(name:"affected", value:"Microsoft Windows Server 2012/2012R2.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3161951");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS16-071");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
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

if(hotfix_check_sp(win2012:1, win2012R2:1) <= 0){
  exit(0);
}

if(!registry_key_exists(key:"SYSTEM\CurrentControlSet\Services\DNS")){
  exit(0);
}

sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

sysVer = fetch_file_version(sysPath:sysPath, file_name:"System32\Dns.exe");
if(!sysVer){
  exit(0);
}

if(hotfix_check_sp(win2012:1, win2012R2:1) > 0)
{
  ## Presently GDR information is not available.
  if(version_is_less(version:sysVer, test_version:"6.2.9200.21872")){
     VULN = TRUE ;
     Vulnerable_range = "Less than 6.2.9200.21872";
  }
}

else if(hotfix_check_sp(win2012R2:1) > 0)
{
  if(version_is_less(version:sysVer, test_version:"6.3.9600.18340")){
    VULN = TRUE ;
    Vulnerable_range = "Less than 6.3.9600.18340";
  }
}

if(VULN)
{
  report = 'File checked:     ' + sysPath + "\system32\Dns.exe" + '\n' +
           'File version:     ' + sysVer  + '\n' +
           'Vulnerable range: ' + Vulnerable_range + '\n' ;
  security_message(data:report);
  exit(0);
}
