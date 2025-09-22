# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.96089");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-06-23 14:20:09 +0200 (Wed, 23 Jun 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"package");
  script_name("Read the Screensaver-Configuration (enabled and lock) on GNOME and KDE");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("IT-Grundschutz");
  script_mandatory_keys("Compliance/Launch/GSHB");
  script_dependencies("compliance_tests.nasl", "find_service.nasl", "gather-package-list.nasl");

  script_tag(name:"summary", value:"Read the Screensaver-Configuration (enabled and lock) on GNOME and KDE.");

  exit(0);
}

include("ssh_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = get_preference("auth_port_ssh");
if(!port)
  port = ssh_get_port(default:22, ignore_unscanned:TRUE);

sock = ssh_login_or_reuse_connection();
if(!sock) {
    error = ssh_get_error();
    if (!error) error = "No SSH Port or Connection!";
    log_message(port:port, data:error);
    set_kb_item(name: "GSHB/gnomescreensaver", value:"error");
    set_kb_item(name: "GSHB/screensaverdaemon", value:"error");
    set_kb_item(name: "GSHB/defkdescreensav", value:"error");
    set_kb_item(name: "GSHB/userkdescreensav", value:"error");
    set_kb_item(name: "GSHB/gnomescreensaver/log", value:error);
    exit(0);
}

gnomescreensaver = ssh_cmd(socket:sock, cmd:"LANG=C gconftool-2 -a /apps/gnome-screensaver");
screensaverdaemon = ssh_cmd(socket:sock, cmd:"LANG=C gconftool-2 -a /apps/gnome_settings_daemon/screensaver");

lstkdescreensav = ssh_cmd(socket:sock, cmd:"LANG=C find /home/ -name kscreensaverrc");
defkdescreensav = ssh_cmd(socket:sock, cmd:"LANG=C cat /etc/kde4/share/config/kscreensaverrc");

if ("FIND: Invalid switch" >< lstkdescreensav|| "FIND: Parameterformat falsch" >< lstkdescreensav){
  set_kb_item(name: "GSHB/gnomescreensaver", value:"windows");
  set_kb_item(name: "GSHB/screensaverdaemon", value:"windows");
  set_kb_item(name: "GSHB/defkdescreensav", value:"windows");
  set_kb_item(name: "GSHB/userkdescreensav", value:"windows");
  exit(0);
}

if (defkdescreensav =~ ".*cannot open /etc/kde4/share/config/kscreensaverrc.*" ||  defkdescreensav =~ ".*No such file or directory.*") defkdescreensav = "none";

if (!gnomescreensaver) gnomescreensaver = "none";
#if (!screensaverdaemon) screensaverdaemon = "none";
if (!lstkdescreensav) lstkdescreensav = "none";
if (!defkdescreensav) defkdescreensav = "none";

if (gnomescreensaver != "none"){
  if ("start_screensaver = true" >< screensaverdaemon)screensaverdaemon = "true";
  else if (!screensaverdaemon) screensaverdaemon = "none";
  else screensaverdaemon = "false";
  val1 ="";
  val2 ="";
  val3 ="";
  val4 ="";
  Lst = split(gnomescreensaver, keep:0);
  for(i=0; i<max_index(Lst); i++){
    if (Lst[i] == " lock_enabled = true") val1 = "true";
    if (Lst[i] == " idle_activation_enabled = true") val2 = "true";
    if (Lst[i] == " idle-delay = 9000" ) val3 = "true";
    if (Lst[i] == " lock-delay = 0" ) val4 = "true";
  }

  if (val1 == "true" && val2 == "true") gnomescreensaver = "true";
  else gnomescreensaver = "false";

  if (val3 == "true" && val4 == "true") set_kb_item(name:"GSHB/gnometimeout",value:"9000");
  else set_kb_item(name:"GSHB/gnometimeout",value:"0");
}
else if (defkdescreensav != "none"){
  val1 ="";
  val2 ="";
  Lst = split(defkdescreensav, keep:0);
  for(i=0; i<max_index(Lst); i++){
    if (Lst[i] == "Enabled=true") val1 = "true";
    if (Lst[i] == "Lock=true") val2 = "true";
    if ( Lst[i] >< "Timeout" ){
      time_out = eregmatch(string: Lst[i], pattern:'Timeout=([0-9]+)');
      if( time_out[1] ){
        set_kb_item(name:"GSHB/defkdetimeout", value:time_out[1]);
      }
    }
  }
  if (val1 == "true" && val2 == "true") defkdescreensav = "true";
  else defkdescreensav = "false";


  if (lstkdescreensav != "none"){
    lstLst = split(lstkdescreensav, keep:0);
    if (max_index(lstLst) > 1){
      for(i=0; i<max_index(lstLst); i++){
        val1 ="";
        val2 ="";
        val3 = ssh_cmd(socket:sock, cmd:"cat " + lstLst[i]);
        Lst = split(val3, keep:0);
        for(i=0; i<max_index(Lst); i++){
          if (Lst[i] == "Enabled=false") val1 = "false";
          else if (Lst[i] == "Enabled=true") val1 = "true";
          if (Lst[i] == "Lock=true") val2 = "true";
          if ( Lst[i] >< "Timeout" ){
            time_out = eregmatch(string: Lst[i], pattern:'Timeout=([0-9]+)');
            if( time_out[1] ){
              set_kb_item(name:"GSHB/lstkdetimeout", value:time_out[1]);
            }
          }
        }
        if ((val1 != "false" || val1 == "true") && val2 == "true") valtmp += "true";
        else valtmp += "false";
      }
      if ("false" >< valtmp)lstkdescreensav = "false";
      else lstkdescreensav = "true";
    }else{
      val1 ="";
      val2 ="";
      val3 = ssh_cmd(socket:sock, cmd:"cat " + lstkdescreensav);
      Lst = split(val3, keep:0);
      for(i=0; i<max_index(Lst); i++){
        if (Lst[i] == "Enabled=false") val1 = "false";
        else if (Lst[i] == "Enabled=true") val1 = "true";
        if (Lst[i] == "Lock=true") val2 = "true";
      }
      if ((val1 != "false" || val1 == "true") && val2 == "true") lstkdescreensav = "true";
      else lstkdescreensav = "false";
    }
  }
}

if (!screensaverdaemon) screensaverdaemon = "none";

set_kb_item(name: "GSHB/gnomescreensaver", value:gnomescreensaver);
set_kb_item(name: "GSHB/screensaverdaemon", value:screensaverdaemon);
set_kb_item(name: "GSHB/defkdescreensav", value:defkdescreensav);
set_kb_item(name: "GSHB/userkdescreensav", value:lstkdescreensav);
exit(0);
