# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800505");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-01-19 13:47:40 +0100 (Mon, 19 Jan 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-0133");
  script_name("Microsoft HTML Help Workshop buffer overflow vulnerability");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/7727");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/33189");
  script_xref(name:"URL", value:"http://en.securitylab.ru/nvd/366501.php");
  script_xref(name:"URL", value:"http://www.security-database.com/detail.php?alert=CVE-2009-0133");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Windows");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);

  script_tag(name:"impact", value:"Successful remote exploitation could context-dependent attackers
  to execute arbitrary code via a .hhp file with a long index file field.");

  script_tag(name:"affected", value:"Microsoft HTML Help Workshop 4.74 and prior.");

  script_tag(name:"insight", value:"A flaw is due to the way application handle a malformed HTML help workshop
  project.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"Microsoft HTML Help Workshop is prone to a buffer overflow vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_xref(name:"URL", value:"http://office.microsoft.com/en-us/orkXP/HA011362801033.aspx");
  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

wsPath = registry_get_sz(item:"Path",
         key:"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\hhw.exe");
if(!wsPath){
  exit(0);
}

share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:wsPath);
file =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1",
                     string:wsPath + "\hhw.exe");

wsVer = GetVer(file:file, share:share);
if(!wsVer){
  exit(0);
}

if(version_is_less_equal(version:wsVer, test_version:"4.74.8702.0")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
