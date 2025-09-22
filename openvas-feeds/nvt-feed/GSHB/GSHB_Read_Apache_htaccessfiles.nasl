# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.96021");
  script_version("2024-02-28T14:37:42+0000");
  script_tag(name:"last_modification", value:"2024-02-28 14:37:42 +0000 (Wed, 28 Feb 2024)");
  script_tag(name:"creation_date", value:"2009-10-23 12:32:24 +0200 (Fri, 23 Oct 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"registry");
  script_name("Reading Apache htaccess Files - Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("IT-Grundschutz");
  script_mandatory_keys("Compliance/Launch/GSHB");
  script_dependencies("smb_reg_service_pack.nasl", "GSHB/GSHB_WMI_Apache.nasl");

  script_tag(name:"summary", value:"Reading Apache htaccess Files.

  This script gets the AuthUserFile configuration of a list of Apache htaccess files.");

  exit(0);
}

include("GSHB_read_file.inc");
include("smb_nt.inc");

htaccessList = get_kb_item("WMI/Apache/htaccessList");

if ("None" >< htaccessList){
  set_kb_item(name:"GSHB/Apache/AccessPWD", value:"None");
  log_message(port:0, proto:"IT-Grundschutz", data:string("No Apache Installed") + string("\n"));
  exit(0);
}


if(!get_kb_item("SMB/WindowsVersion")){
  set_kb_item(name:"GSHB/ApacheConfig", value:"error");
  set_kb_item(name:"GSHB/ApacheConfig/log", value:string("No access to SMB host.\nFirewall is activated or there is not a Windows system."));
  exit(0);
}

if(htaccessList){

  htaccessList = split(htaccessList, sep:'|', keep:FALSE);

  for (h=0; h<max_index(htaccessList); h++) {

    if (htaccessList[h] >!< 'Name' || ''){
      path = htaccessList[h];
      path = split(path, sep:":", keep:FALSE);
      file = ereg_replace(pattern:'\\\\', replace:'\\', string:path[1]);
      share = path[0] + "$";
      htaccessfile = GSHB_read_file(share: share, file: file, offset: 0);
      if (!htaccessfile){
        log_message(port:0, proto:"IT-Grundschutz", data:"Cannot access/open the Apache .htaccess file.");
      } else {
        AccessPWD = egrep(pattern:'^ *AuthUserFile *', string:htaccessfile);
        AccessPWD = ereg_replace(pattern:'^ *AuthUserFile *|\"|\n|\r',replace:'', string:AccessPWD);
        KB = KB + AccessPWD + "|";
      }
    }
  }
}
else
  KB = "None";

set_kb_item(name:"GSHB/Apache/AccessPWD", value:KB);
exit(0);
