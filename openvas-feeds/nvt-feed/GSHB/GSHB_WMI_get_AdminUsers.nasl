# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.96030");
  script_version("2025-03-07T05:38:18+0000");
  script_tag(name:"last_modification", value:"2025-03-07 05:38:18 +0000 (Fri, 07 Mar 2025)");
  script_tag(name:"creation_date", value:"2009-10-23 12:32:24 +0200 (Fri, 23 Oct 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"registry");
  script_name("Get all Windows Admin Users and Groups over WMI - Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("IT-Grundschutz");
  script_mandatory_keys("Compliance/Launch/GSHB", "Tools/Present/wmi");
  script_dependencies("smb_reg_service_pack.nasl", "GSHB/GSHB_WMI_OSInfo.nasl", "lsc_options.nasl");
  script_exclude_keys("win/lsc/disable_win_cmd_exec");

  script_tag(name:"summary", value:"Get all Windows non System Services and Eventlog Servicestate
  over WMI.");

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
    set_kb_item(name:"WMI/LocalWindowsAdminUsers", value:"error");
    set_kb_item(name:"WMI/LocalWindowsAdminUsers/log", value:"No access to SMB host.\nFirewall is activated or there is not a Windows system.");
    exit(0);
}

LOCUSRGRP = powershell_wmi_user_groupuser();
LOCUSRGRP = tolower(LOCUSRGRP);
LOCUSRGRP = split(LOCUSRGRP, sep:'\n', keep:0);
LOCUSRS = "";

for(i=1; i<max_index(LOCUSRGRP); i++)
  {
    LOCUSRGRPinf = split(LOCUSRGRP[i], sep:"|", keep:0);
    LocGrpLst = eregmatch(pattern:'name="[^\"]+', string:LOCUSRGRPinf[0]);
    LocGrpLst[0] = ereg_replace(pattern:'name="', string:LocGrpLst[0], replace:"");
    if("admin" >< LocGrpLst[0])
    {
        LocUsrLst = eregmatch(pattern:'name="[^\"]+', string:LOCUSRGRPinf[1]);
        LocUsrLst[0] = ereg_replace(pattern:'name="', string:LocUsrLst[0], replace:"");

        if (LocUsrLst[0] >!< LOCUSRS)
        {
           LOCUSRS = LOCUSRS + LocUsrLst[0] + '|';
        }
     }
  }

QLOCUSRS =split(LOCUSRS, sep:"|", keep:0);

for(o=1; o<max_index(LOCUSRGRP); o++)
{
    OLOCUSRGRPinf = split(LOCUSRGRP[o], sep:"|", keep:0);
    OLocGrpLst = eregmatch(pattern:'name="[^\"]+', string:OLOCUSRGRPinf[0]);
    OLocGrpLst[0] = ereg_replace(pattern:'name="', string:OLocGrpLst[0], replace:"");
    for(Q=1; Q<max_index(QLOCUSRS); Q++)
    {
        if(QLOCUSRS[Q] >< OLocGrpLst[0])
        {
            OLocUsrLst = eregmatch(pattern:'name="[^\"]+', string:OLOCUSRGRPinf[1]);
            OLocUsrLst[0] = ereg_replace(pattern:'name="', string:OLocUsrLst[0], replace:"");
            if (OLocUsrLst[0] >!< LOCUSRS )
            {
               LOCUSRS = LOCUSRS + OLocUsrLst[0] + '|';
            }
         }
    }
}


set_kb_item(name:"WMI/LocalWindowsAdminUsers", value:LOCUSRS);
exit(0);
