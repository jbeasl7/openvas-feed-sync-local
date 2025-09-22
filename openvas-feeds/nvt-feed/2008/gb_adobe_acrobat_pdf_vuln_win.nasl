# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800078");
  script_version("2024-02-15T05:05:39+0000");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:39 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2008-12-10 17:58:14 +0100 (Wed, 10 Dec 2008)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2008-5331");
  script_name("Adobe Acrobat 9 PDF Document Encryption Weakness Vulnerability - Windows");
  script_xref(name:"URL", value:"http://blogs.adobe.com/security/2008/12/acrobat_9_and_password_encrypt.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/32610");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Windows");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_tag(name:"impact", value:"Successful exploitation could allow attackers to steal or guess document's
  password via a brute force attacks.");
  script_tag(name:"affected", value:"Adobe Acrobat version 9.0 on Windows.");
  script_tag(name:"insight", value:"The flaw is due to the way it handles encryption standards.");
  script_tag(name:"solution", value:"Upgrade Adobe Acrobat version 9.3.2 or later.");
  script_tag(name:"summary", value:"Adobe Acrobat is prone to an encryption weakness vulnerability.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("smb_nt.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

if(!registry_key_exists(key:"SOFTWARE\Adobe")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
if(!registry_key_exists(key:key)){
    exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  adobeName = registry_get_sz(item:"DisplayName", key:key +item);
  if("Adobe Acrobat" >< adobeName)
  {
    adobeVer = registry_get_sz(item:"DisplayVersion", key:key + item);
    if(!adobeVer){
      exit(0);
    }

    if(adobeVer =~ "^9\.0(\.0)?$"){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
    exit(0);
  }
}
