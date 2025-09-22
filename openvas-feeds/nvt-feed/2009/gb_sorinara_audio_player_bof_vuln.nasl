# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900649");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2009-05-29 07:35:11 +0200 (Fri, 29 May 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-1644", "CVE-2009-2568");
  script_name("Sorinara Streaming Audio Player Stack Overflow Vulnerability");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/8640");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34842");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34861");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/8625");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/50369");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/8620");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/8617");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/50339");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_tag(name:"impact", value:"Successful exploitation will let the attacker execute arbitrary
codes in the context of the affected system and cause the application to crash
by overflowing the stack memory location.");
  script_tag(name:"affected", value:"Sorinara Streaming Audio Player version 0.9 and prior");
  script_tag(name:"insight", value:"This vulnerability is due to an improper boundary checks when
processing playlist 'pla' and '.m3u' files.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"Sorinara Streaming Audio Player is prone to Stack Overflow Vulnerability.");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\SAP\";
vendName = registry_get_sz(key:key, item:"DisplayName");
if("SAP" >< vendName)
{
  readmePath = registry_get_sz(key:key, item:"UninstallString");
  if(!readmePath){
    exit(0);
  }

  readmePath = readmePath - "\uninstall.exe /uninstall";
  readmePath = readmePath + "\Help";
  readmeText = smb_read_file(fullpath:readmePath + "\index.htm", offset:0, count:4500);
  if(!readmeText){
    exit(0);
  }

  sapVer = eregmatch(pattern:"SAP ([0-9.]+)", string:readmeText);
  if(sapVer[1] != NULL)
  {
    if(version_is_less_equal(version:sapVer[1], test_version:"0.9")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
  }
}
