# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800122");
  script_version("2023-07-28T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-07-28 05:05:23 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-10-31 15:07:51 +0100 (Fri, 31 Oct 2008)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-4779");
  script_name("TUGzip zip File Buffer Overflow Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/32411");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/31913");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/6831");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/46120");
  script_xref(name:"URL", value:"http://www.frsirt.com/english/advisories/2008/2918");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_tag(name:"impact", value:"Successful exploitation allows attackers to execute arbitrary code by
  tricking a user into opening a specially crafted archive or can even
  crash an affected application.");
  script_tag(name:"affected", value:"TUGzip Version 3.5.0.0 and prior on Windows (Any).");
  script_tag(name:"insight", value:"The flaw exists due to boundary error while processing an archive containing
  an overly long file or directory name.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"TUGzip is prone to a buffer overflow vulnerability.");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

appPath = registry_get_sz(item:"Inno Setup: App Path",
          key:"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\TUGZip_is1");
if(!appPath){
  exit(0);
}

exePath = appPath + "\TUGZip.exe";
share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:exePath);
file =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:exePath);

tugZipVer = GetVer(file:file, share:share);
if(!tugZipVer){
  exit(0);
}

if(version_is_less_equal(version:tugZipVer, test_version:"3.5.0.0")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
