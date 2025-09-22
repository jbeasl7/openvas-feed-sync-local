# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902817");
  script_version("2025-03-05T05:38:53+0000");
  script_cve_id("CVE-2012-0008");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:53 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2012-03-14 10:10:10 +0530 (Wed, 14 Mar 2012)");
  script_name("Microsoft Visual Studio Privilege Elevation Vulnerability (2651019)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_ms_visual_prdts_detect.nasl");
  script_mandatory_keys("Microsoft/VisualStudio/Ver");
  script_require_ports(139, 445);
  script_tag(name:"impact", value:"Successful exploitation could allow attacker to execute arbitrary code with
  elevated privileges.");
  script_tag(name:"affected", value:"- Microsoft Visual Studio 2008 SP 1 and prior

  - Microsoft Visual Studio 2010 SP 1 and prior");
  script_tag(name:"insight", value:"The flaw is due to the application loading add-ins from insecure paths.
  This can be exploited to gain additional privileges by placing malicious add-
  ins in certain directories and tricking a user into starting Visual Studio.");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"summary", value:"This host is missing an important security update according to
  Microsoft Bulletin MS12-021.");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2669970");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52329");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2645410");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2645410");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1026792");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2012/ms12-021");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

## MS12-021 Hotfix check
if((hotfix_missing(name:"2669970") == 0) && (hotfix_missing(name:"2644980") == 0) &&
   (hotfix_missing(name:"2645410") == 0)){
  exit(0);
}

vsVer = get_kb_item("Microsoft/VisualStudio/Ver");
if(!vsVer){
  exit(0);
}

if(vsVer =~ "^9\..*")
{
  vsPath = registry_get_sz(key:"SOFTWARE\Microsoft\VSA\9.0", item:"InstallDir");
  if(!vsPath){
    exit(0);
  }

  exeVer = fetch_file_version(sysPath:vsPath, file_name:"Vsaenv.exe");

  if(exeVer && version_is_less(version:exeVer, test_version:"9.0.30729.5797"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

if(vsVer =~ "^10\..*")
{
  vsPath = registry_get_sz(key:"SOFTWARE\Microsoft\VisualStudio\10.0", item:"InstallDir");
  if(!vsPath){
    exit(0);
  }

  dllVer = fetch_file_version(sysPath:vsPath, file_name:"ShellExtensions\Platform\AppenvStub.dll");

  ## Visual Studio 2010 SP1 version 10 < 10.0.40219.377
  if(dllVer && (version_is_less(version:dllVer, test_version:"10.0.30319.552") ||
     version_in_range(version:dllVer, test_version:"10.0.40000.000", test_version2:"10.0.40219.376"))){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
