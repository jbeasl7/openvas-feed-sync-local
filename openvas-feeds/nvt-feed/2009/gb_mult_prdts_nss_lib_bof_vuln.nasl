# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800920");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-08-11 07:36:16 +0200 (Tue, 11 Aug 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-2404");
  script_name("Multiple Products NSS Library Buffer Overflow Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/36102");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35891");
  script_xref(name:"URL", value:"http://rhn.redhat.com/errata/RHSA-2009-1185.html");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=512912");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);

  script_tag(name:"impact", value:"Successful exploitation will let the attacker execute arbitrary code in
  the context of the affected application and may lead to denial of service.");

  script_tag(name:"affected", value:"Firefox/Thunderbird/SeaMonkey/Evolution/Pidgin/AOL Instant Messenger
  containing NSS library before 3.12.3.");

  script_tag(name:"insight", value:"A flaw exists in the regular expression parser used in the NSS library to match
  common names in certificates and may result in a heap based buffer overflow.
  It can be exploited via a long domain name in the subject's Common Name (CN)
  field of an X.509 certificate, related to the cert_TestHostName function.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Upgrade to NSS library 3.12.3 or later.");

  script_tag(name:"summary", value:"Firefox or Thunderbird or SeaMonkey or Evolution or Pidgin or AOL Instant Messenger Product(s) is prone to a buffer overflow vulnerability.");

  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";

if(!registry_key_exists(key:key)) {
    exit(0);
}

commonPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion\",
                             item:"ProgramFilesDir");

if(!commonPath){
  exit(0);
}

share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:commonPath);
allFiles = make_list();

foreach item (registry_enum_keys(key:key))
{
  prdtName = registry_get_sz(key:key + item, item:"DisplayName");
  if(prdtName == "Evolution")
  {
    evolutionPath = registry_get_sz(key:key + item, item:"InstallLocation");
    if(evolutionPath)
    {
      evolutionFile = evolutionPath + "\bin\nss3.dll";
      allFiles = make_list(allFiles, evolutionFile);
    }
  }
  else if("AOL Instant Messenger" >< prdtName)
  {
    aolFile = commonPath + "\AIM\nss3.dll";
    allFiles = make_list(allFiles, aolFile);
  }
  else if("AIM" >< prdtName)
  {
    aimPath = registry_get_sz(key:key + item, item:"UninstallString");
    if(aimPath)
    {
      aimFile = aimPath - "\uninst.exe" + "\nss3.dll";
      allFiles = make_list(allFiles, aimFile);
    }
  }
  else if("Firefox" >< prdtName)
  {
    firefoxFile = commonPath + "\Mozilla Firefox\nss3.dll";
    allFiles = make_list(allFiles, firefoxFile);
  }
  else if ("Thunderbird" >< prdtName)
  {
    thunderbirdFile = commonPath + "\Mozilla Thunderbird\nss3.dll";
    allFiles = make_list(allFiles, thunderbirdFile);
  }
  else if ("Pidgin" >< prdtName){
    pidginFile = commonPath + "\Pidgin\nss3.dll";
    allFiles = make_list(allFiles, pidginFile);
  }
  else if ("SeaMonkey" >< prdtName){
    seamonkeyFile = commonPath + "\mozilla.org\SeaMonkey\nss3.dll";
    allFiles = make_list(allFiles, seamonkeyFile);
  }
}

foreach prdtFile (allFiles)
{
  file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:prdtFile);
  dllVer = GetVer(share:share, file:file);

  if((dllVer != NULL) && version_is_less(version:dllVer, test_version:"3.12.3"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}
