# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.96040");
  script_version("2025-03-06T05:38:27+0000");
  script_tag(name:"last_modification", value:"2025-03-06 05:38:27 +0000 (Thu, 06 Mar 2025)");
  script_tag(name:"creation_date", value:"2009-10-23 12:32:24 +0200 (Fri, 23 Oct 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"registry");
  script_name("Pre-Windows 2000 Compatible Access - Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("IT-Grundschutz");
  script_mandatory_keys("Compliance/Launch/GSHB", "Tools/Present/wmi");
  script_dependencies("smb_reg_service_pack.nasl", "GSHB/GSHB_WMI_OSInfo.nasl", "lsc_options.nasl");
  script_exclude_keys("win/lsc/disable_win_cmd_exec");

  script_tag(name:"summary", value:"The script checks, if Everyone in the Usergroup Pre-Windows
  2000 Compatible Access.");

  exit(0);
}

include("wmi_user.inc");
include("smb_nt.inc");
include("powershell_func.inc");

if(is_win_cmd_exec_disabled())
  exit(0);

host    = get_host_ip();
usrname = kb_smb_login();
domain  = kb_smb_domain();
if (domain){
  usrname = domain + '\\' + usrname;
}
passwd = kb_smb_password();

OSVER = get_kb_item("WMI/WMI_OSVER");


if(!OSVER || "none" >< OSVER){
    set_kb_item(name:"WMI/AdminUsers", value:"error");
    set_kb_item(name:"WMI/AdminUsers/log", value:"No access to SMB host.\nFirewall is activated or there is not a Windows system.");
    exit(0);
}

Everyone = "None";
PreWin2000 = "None";

sysLst = powershell_wmi_user_sysaccount();
usrLst = powershell_wmi_user_useraccount();
grpLst = powershell_wmi_user_group();
usrgrplist = powershell_wmi_user_groupuser();

Lst = sysLst + usrLst + grpLst;

Lst = split(Lst, "\n", keep:0);
for(i=1; i<max_index(Lst); i++)
{
  if("Domain|Name|SID" >< Lst[i]){
    continue;
  }
  desc = split(Lst[i], sep:"|", keep:0);
  if(desc !=NULL)
  {
        if(desc[2] == "S-1-1-0") Everyone = desc[1];
        if(desc[2] == "S-1-5-32-554") PreWin2000 = desc[1];
  }
}

usrgrplist = split(usrgrplist, sep:'\n', keep:0);

for(u=1; u<max_index(usrgrplist); u++)
{
  usrgrplistinf = split(usrgrplist[u], sep:"|", keep:0);
  PreGrpLst = eregmatch(pattern:PreWin2000, string:usrgrplistinf[0]);
  if (PreWin2000 == PreGrpLst[0])
  {
    PreUsrLst = eregmatch(pattern:Everyone, string:usrgrplistinf[1]);
    PreWin2000Usr = PreUsrLst[0];
  }
}

if(!PreWin2000Usr) PreWin2000Usr = "None";

set_kb_item(name:"WMI/PreWin2000Usr", value:PreWin2000Usr);

exit(0);
