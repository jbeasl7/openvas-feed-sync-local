# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800106");
  script_version("2023-07-28T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-07-28 05:05:23 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-10-01 17:01:16 +0200 (Wed, 01 Oct 2008)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-2641");
  script_xref(name:"CB-A", value:"08-0105");
  script_name("Adobe Reader/Acrobat JavaScript Method Handling Vulnerability (APSB08-15) - Windows");
  script_xref(name:"URL", value:"http://secunia.com/advisories/30832");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/29908");
  script_xref(name:"URL", value:"http://www.frsirt.com/english/advisories/2008/1906/products");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb08-15.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_tag(name:"impact", value:"Successful exploitation allows remote attackers to execute arbitrary code
  or an attacker could take complete control of an affected system or cause
  a denial of service condition.");
  script_tag(name:"affected", value:"Adobe Reader version 7.0.9 and prior

  Adobe Reader versions 8.0 through 8.1.2

  Adobe Acrobat Professional version 7.0.9 and prior

  Adobe Acrobat Professional versions 8.0 through 8.1.2");
  script_tag(name:"insight", value:"The flaw is due to an input validation error in a JavaScript method,
  which could allow attackers to execute arbitrary code by tricking a user
  into opening a specially crafted PDF document.");
  script_tag(name:"solution", value:"Apply the security update from the referenced advisory.");
  script_tag(name:"summary", value:"Adobe Reader/Acrobat is prone to a remote code execution (RCE)
  vulnerability.");
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

keys = registry_enum_keys(key:key);

foreach item (keys)
{
  adobeName = registry_get_sz(item:"DisplayName", key:key +item);

  if("Adobe Reader" >< adobeName || "Adobe Acrobat" >< adobeName)
  {
    adobeVer = registry_get_sz(item:"DisplayVersion", key:key + item);
    if(!adobeVer){
      exit(0);
    }

    if(adobeVer == "8.1.2" && adobeName =~ "Security Update ?[0-9]+"){
      exit(0);
    }

    if(adobeVer =~ "^(7\.0(\.[0-9])?|8\.0(\..*)?|8\.1(\.[0-2])?)$"){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
    exit(0);
  }
}
