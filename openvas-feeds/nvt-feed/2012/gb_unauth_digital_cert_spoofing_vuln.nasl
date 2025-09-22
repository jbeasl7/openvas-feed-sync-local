# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802634");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-06-04 14:14:14 +0530 (Mon, 04 Jun 2012)");
  script_name("Microsoft Windows Unauthorized Digital Certificates Spoofing Vulnerability (2718704)");
  script_xref(name:"URL", value:"http://securitytracker.com/id/1027114");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2718704");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/SecurityAdvisories/2012/2718704");
  script_xref(name:"URL", value:"http://www.theregister.co.uk/2012/06/04/microsoft_douses_flame/print.html");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Windows");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to spoof content, perform
  phishing attacks or perform man-in-the-middle attacks.");
  script_tag(name:"affected", value:"- Microsoft Windows 7 Service Pack 1 and prior

  - Microsoft Windows XP Service Pack 3 and prior

  - Microsoft Windows Vista Service Pack 2 and prior

  - Microsoft Windows Server 2003 Service Pack 2 and prior

  - Microsoft Windows Server 2008 Service Pack 2 and prior");
  script_tag(name:"insight", value:"The flaw is due to unauthorized digital certificates derived from a Microsoft
  Certificate Authority. An unauthorized certificate could be used to spoof
  content, perform phishing attacks, or perform man-in-the-middle attacks.");
  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");
  script_tag(name:"summary", value:"Microsoft Windows operating system is prone to a digital certificates spoofing vulnerability.");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(xp:4, xpx64:3, win2003:3, win2003x64:3, winVista:3,
                   win7:2, win7x64:2, win2008:3, win2008r2:2) <= 0){
  exit(0);
}

## Untrusted Certificates Path
key = "SOFTWARE\Microsoft\SystemCertificates\Disallowed\Certificates\";
if(!registry_key_exists(key:key)) {
  exit(0);
}

## The invalid certificates and their thumbprints
certs = make_list(
        ## Microsoft Enforced Licensing Intermediate PCA
        "2A83E9020591A55FC6DDAD3FB102794C52B24E70",
        ## Microsoft Enforced Licensing Intermediate PCA
        "3A850044D8A195CD401A680C012CB0A3B5F8DC08",
        ## Microsoft Enforced Licensing Registration Authority CA (SHA1)
        "FA6660A94AB45F6A88C0D7874D89A863D74DEE97"
        );

## Verify that the certificates have been added to the Untrusted Certificates
foreach cert (certs)
{
  if(! registry_key_exists(key: key+cert))
  {
    flag = TRUE;
    break;
  }
}

## File information is not available for Windows 7, Vista and 2008
if(flag && hotfix_check_sp(winVista:3, win2008:3, win7:2, win7x64:2, win2008r2:2) > 0)
{
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
}

sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

dllVer = fetch_file_version(sysPath:sysPath, file_name:"system32\Crypt32.dll");
if(!dllVer){
  exit(0);
}

if(hotfix_check_sp(xp:4) > 0)
{
  if(version_is_less(version:dllVer, test_version:"5.131.2600.6237")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

else if(hotfix_check_sp(win2003:3, win2003x64:3, xpx64:3) > 0)
{
  if(version_is_less(version:dllVer, test_version:"5.131.3790.5012")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}
