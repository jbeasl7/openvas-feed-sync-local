# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800568");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2023-07-27T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:09 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-05-13 10:01:19 +0200 (Wed, 13 May 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("ElectraSoft 32bit FTP Version Detection");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_tag(name:"summary", value:"This script detects the version of ElectraSoft 32bit FTP.");
  exit(0);
}


include("smb_nt.inc");
include("secpod_smb_func.inc");
include("cpe.inc");
include("host_details.inc");

SCRIPT_DESC = "ElectraSoft 32bit FTP Version Detection";

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\32bit FTP";
vendName = registry_get_sz(key:key, item:"Publisher");
if("ElectraSoft" >< vendName)
{
  readmePath = registry_get_sz(key:key, item:"InstallLoaction");
  if(!readmePath){
    exit(0);
  }

  readmeText = smb_read_file(fullpath:readmePath + "\README.TXT", offset:0, count:100);
  if(!readmeText){
    exit(0);
  }
  ftpVer = eregmatch(pattern:"32bit FTP ([0-9.]+)", string:readmeText);
  if(ftpVer[1])
  {
    set_kb_item(name:"ElectraSoft/FTP/Ver", value:ftpVer[1]);
    log_message(data:"ElectraSoft FTP version " +ftpVer[1] + " running at" +
                       " location " + readmePath + " was detected on the host");

    cpe = build_cpe(value:ftpVer[1], exp:"^([0-9.]+)", base:"cpe:/a:electrasoft:32bit_ftp:");
    if(!isnull(cpe))
       register_host_detail(name:"App", value:cpe, desc:SCRIPT_DESC);

  }
}
