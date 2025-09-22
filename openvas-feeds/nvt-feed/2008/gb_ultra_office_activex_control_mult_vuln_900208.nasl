# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900208");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2008-09-02 07:39:00 +0200 (Tue, 02 Sep 2008)");
  script_cve_id("CVE-2008-3878");
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_name("Ultra Office ActiveX Control Multiple Vulnerabilities");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);

  script_xref(name:"URL", value:"http://secunia.com/advisories/31632/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/30861");
  script_xref(name:"URL", value:"http://www.juniper.net/security/auto/vulnerabilities/vuln30861.html");

  script_tag(name:"summary", value:"Ultra Office Control is prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"Error exists when handling parameters received by the HttpUpload()
  and Save() methods in OfficeCtrl.ocx file.");

  script_tag(name:"affected", value:"Ultra Office Control 2.x and prior versions on Windows (All).");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"impact", value:"Successful exploitation will allow execution of arbitrary
  code, stack-based buffer overflow, can overwrite arbitrary files on the vulnerable system by
  tricking a user into visiting a malicious website.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("smb_nt.inc");
include("secpod_smb_func.inc");

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";

foreach entry(registry_enum_keys(key:key)) {
  if(entry && "Ultra Office Control" >< entry) {
    appInsLoc = registry_get_sz(item:"InstallLocation", key:key + entry);
    if(!appInsLoc){
      exit(0);
    }
    break;
  }
}

if(!appInsLoc){
  exit(0);
}

fileVer = get_version(dllPath:appInsLoc + "OfficeCtrl.ocx");
if(!fileVer){
  exit(0);
}

if(egrep(pattern:"^([01]\..*|2\.0\.[01]?[0-9]?[0-9]?[0-9]\..*|2\.0\.200[0-7]\..*|2\.0\.2008(\.[0-7]?[0-9]?[0-9]|\.80[01]))$", string:fileVer)) {

  clsid = "{00989888-BB72-4E31-A7C6-5F819C24D2F7}";
  regKey = "SOFTWARE\Classes\CLSID\"+ clsid;
  if(registry_key_exists(key:regKey)) {
    activeKey = "SOFTWARE\Microsoft\Internet Explorer\ActiveX Compatibility\" + clsid;
    killBit = registry_get_dword(key:activeKey, item:"Compatibility Flags");
    if(killBit && (int(killBit) == 1024)){
      exit(0);
    }
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}

exit(0);