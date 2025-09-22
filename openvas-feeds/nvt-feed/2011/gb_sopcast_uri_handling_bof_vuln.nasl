# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802281");
  script_version("2023-07-28T05:05:23+0000");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-28 05:05:23 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-12-08 15:15:15 +0530 (Thu, 08 Dec 2011)");
  script_name("SopCast 'sop://' URI Handling Buffer Overflow Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/40940");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50901");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/18200");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/107528/ZSL-2011-5063.txt");
  script_xref(name:"URL", value:"http://www.zeroscience.mk/en/vulnerabilities/ZSL-2011-5063.php");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to execute
arbitrary code in the context of the user running an affected application. Failed
exploit attempts may lead to a denial-of-service condition.");
  script_tag(name:"affected", value:"SopCast version 3.4.7.45585");
  script_tag(name:"insight", value:"The flaw is due to a boundary error in the WebPlayer ActiveX
Control when handling the 'ChannelName' property can be exploited to cause a
stack based buffer overflow via a specially crafted 'sop://' URL string.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"SopCast is prone to a buffer overflow vulnerability.");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\SopCast";
if(!registry_key_exists(key:key)){
  exit(0);
}

sopName = registry_get_sz(key:key, item:"DisplayName");
if("SopCast" >< sopName)
{
  sopPath = registry_get_sz(key:key, item:"DisplayIcon");
  if(!sopPath){
    exit(0);
  }
  sopPath = sopPath - "\SopCast.exe";

  sopVer = fetch_file_version(sysPath:sopPath, file_name:"sopocx.ocx");
  if(! sopVer){
   exit(0);
  }

  if(version_is_equal(version:sopVer, test_version:"3.4.7.45585")) {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
