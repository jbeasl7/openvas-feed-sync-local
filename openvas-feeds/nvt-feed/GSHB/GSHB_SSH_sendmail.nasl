# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.96099");
  script_version("2024-01-10T05:05:17+0000");
  script_tag(name:"last_modification", value:"2024-01-10 05:05:17 +0000 (Wed, 10 Jan 2024)");
  script_tag(name:"creation_date", value:"2010-05-03 15:59:29 +0200 (Mon, 03 May 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Check Sendmail Configuration over SSH");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("IT-Grundschutz");
  script_dependencies("compliance_tests.nasl", "gather-package-list.nasl", "gb_sendmail_smtp_detect.nasl");
  script_mandatory_keys("Compliance/Launch/GSHB");

  script_tag(name:"summary", value:"Check Sendmail Configuration over an SSH Connection.

  The Script checks various configuration parameter and filesystem permissions
  if sendmail is installed.");

  script_tag(name:"qod_type", value:"package");

  exit(0);
}

sendmail = get_kb_item("sendmail/detected");
if (!sendmail){
  set_kb_item(name: "GSHB/SENDMAIL", value:"nosendmail");
  exit(0);
}
else{

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
    set_kb_item(name: "GSHB/SENDMAIL", value:"error");
    set_kb_item(name: "GSHB/SENDMAIL/log", value:error);
    exit(0);
  }

  lssendmailcnf = ssh_cmd(socket:sock, cmd:"ls -l /etc/mail/sendmail.cf");
  lssendmailcnfdir = ssh_cmd(socket:sock, cmd:"ls -ld /etc/mail");
  if (lssendmailcnf =~ ".*(Datei oder Verzeichnis nicht gefunden|No such file or directory).*"){
    loc_sendmailcnf = ssh_cmd(socket:sock, cmd:"locate sendmail.cnf");
    if (!loc_sendmailcnf) loc_sendmailcnf = "not found";
    else if ("locate:" >< loc_sendmailcnf) loc_sendmailcnf = ssh_cmd(socket:sock, cmd:"mlocate sendmail.cnf");
    if (!loc_sendmailcnf) loc_sendmailcnf = "not found";
    else if ("mlocate:" >< loc_sendmailcnf) loc_sendmailcnf = ssh_cmd(socket:sock, cmd:"slocate sendmail.cnf");
    if (!loc_sendmailcnf) loc_sendmailcnf = "not found";
    else if ("slocate:" >< loc_sendmailcnf) loc_sendmailcnf = "not found";
    if ("not found" >!< loc_sendmailcnf){

      Lst = split(loc_sendmailcnf, keep:FALSE);
      for(i=0; i<max_index(Lst); i++){
        if (Lst[i] =~ ".*sendmail.cf$") lssendmailcnf = ssh_cmd(socket:sock, cmd:"ls -l " + Lst[i]);
        if (Lst[i] =~ ".*sendmail.cf$") lssendmailcnfdir = ssh_cmd(socket:sock, cmd:"ls -ld " + Lst[i] - "/sendmail.cf");
      }
    }
    else{
      lssendmailcnf = "none";
      lssendmailcnfdir = "none";
    }
  }
  if("none" >!< lssendmailcnf){
    sendmailcnf = split(lssendmailcnf, sep:" ", keep:FALSE);
    for (i=0; i<max_index(sendmailcnf); i++){
      if(sendmailcnf[i] =~ ".*sendmail.c.*") sendmailcnf = sendmailcnf[i];
    }
  } else sendmailcnf = "none";

  if ("none" >!< sendmailcnf)
  {

    mlocal = ssh_cmd(socket:sock, cmd:"grep Mlocal " + sendmailcnf);
    if (mlocal){
      Lst = split(mlocal, sep:",", keep:FALSE);
      for (i=0; i<max_index(Lst); i++){
        if (Lst[i] =~ "P=.*") mlocalp = Lst[i] + '\n';
      }
      Lst = split(mlocalp, keep:FALSE);
      for (i=0; i<max_index(Lst); i++){
        var = Lst[i] - "P=";
        lsmlocalp += ssh_cmd(socket:sock, cmd:"ls -l " + var) + '\n';
      }
    }
    else{
      mlocal = "none";
      mlocalp = "none";
      lsmlocalp = "none";
    }

    fx = ssh_cmd(socket:sock, cmd:"grep FX " + sendmailcnf);
    if (!fx) fx = "none";

    statusfile = ssh_cmd(socket:sock, cmd:"grep '^O *.tatus.ile' " + sendmailcnf);
    if (statusfile){
      statusfile = split (statusfile, sep:"=", keep:FALSE);
      statusfiledir = split (statusfile[1], sep:"/", keep:FALSE);
      l = max_index(statusfiledir) - 1;
      Lst = "";
      for (i=0; i<l; i++){
        Lst += statusfiledir[i] + "/";
      }
      lsstatusfiledir = ssh_cmd(socket:sock, cmd:"ls -ld " + Lst);
      lsstatusfile = ssh_cmd(socket:sock, cmd:"ls -l " + statusfile[1]);
      statusfile = statusfile[1];
      statusfiledir = Lst;
      if (lsstatusfile =~ ".*(Datei oder Verzeichnis nicht gefunden|No such file or directory).*") lsstatusfile = "nofile";
    }else{
      lsstatusfiledir = "none";
      lsstatusfile = "none";
      statusfile = "none";
      statusfiledir = "none";
    }

    loc_forward = ssh_cmd(socket:sock, cmd:"locate .forward");
    if (!loc_forward) loc_forward = "not found";
    else if ("locate:" >< loc_forward) loc_forward = ssh_cmd(socket:sock, cmd:"mlocate .forward");
    if (!loc_forward) loc_forward = "not found";
    else if ("mlocate:" >< loc_forward) loc_forward = ssh_cmd(socket:sock, cmd:"slocate .forward");
    if (!loc_forward) loc_forward = "not found";
    else if ("slocate:" >< loc_forward) loc_forward = "not found";
    if (!loc_forward) loc_forward = "not found";
    if ("not found" >!< loc_forward){
      Lst = split(loc_forward, keep:FALSE);
      for(i=0; i<max_index(Lst); i++){
        lsforward += ssh_cmd(socket:sock, cmd:"ls -l " + Lst[i]) + '\n';
      }
    }
    else lsforward = "none";

    queuedir = ssh_cmd(socket:sock, cmd:"grep '^O *.ueue.irectory' " + sendmailcnf);
    if (queuedir){
      queuedir = split (queuedir, sep:"=", keep:FALSE);
      lsqueuedir = ssh_cmd(socket:sock, cmd:"ls -ld " + queuedir[1]);
      queuedir = queuedir[1];
      lsqueue = ssh_cmd(socket:sock, cmd:"ls -l " + queuedir);
      if (lsqueue =~ ".*(Keine Berechtigung|Permission denied).*") lsqueue ="noperm";
    }else{
      queuedir = "none";
      lsqueuedir = "none";
      lsqueue = "none";
    }

  aliases = ssh_cmd(socket:sock, cmd:"grep '^O *.lias.ile' " + sendmailcnf);
    if (aliases){
      aliases = ereg_replace (string:aliases, pattern:'\n', replace:"");
      aliaspath = split (aliases, sep:"=", keep:FALSE);
      aliaspath = aliaspath[1];
      aliases = ssh_cmd(socket:sock, cmd:"cat " + aliaspath);
      incaliases = ssh_cmd(socket:sock, cmd:"grep :include: " + aliaspath);
      if (!incaliases || incaliases == "") incaliases = "none";
      lsaliases = ssh_cmd(socket:sock, cmd:"ls -l " + aliaspath);
      lsaliasesdb = ssh_cmd(socket:sock, cmd:"ls -l " + aliaspath + ".db");
    }
    else{
      aliases = "none";
      aliasepath = "none";
      incaliases = "none";
      lsaliases = "none";
      lsaliasesdb = "none";
    }
  }
}

if(!ssendmailcnf)ssendmailcnf = "none";
if(!lssendmailcnfdir)lssendmailcnfdir = "none";
if(!sendmailcnf)sendmailcnf = "none";
if(!mlocalp)mlocalp = "none";
if(!lsmlocalp)lsmlocalp = "none";
if(!lsstatusfiledir)lsstatusfiledir = "none";
if(!lsstatusfile)lsstatusfile = "none";
if(!statusfile)statusfile = "none";
if(!statusfiledir)statusfiledir = "none";
if(!fx)fx = "none";
if(!mlocal)mlocal = "none";
if(!lsforward)lsforward = "none";
if(!queuedir)queuedir = "none";
if(!lsqueuedir)lsqueuedir = "none";
if(!lsqueue)lsqueue = "none";
if(!aliases)aliases = "none";
if(!aliaspath)aliaspath = "none";
if(!incaliases)incaliases = "none";
if(!lsaliases)lsaliases = "none";
if(!lsaliasesdb)lsaliasesdb = "none";

set_kb_item(name: "GSHB/SENDMAIL/LSMAILCNF", value:lssendmailcnf);
set_kb_item(name: "GSHB/SENDMAIL/lssendmailcnfdir", value:lssendmailcnfdir);
set_kb_item(name: "GSHB/SENDMAIL/sendmailcnf", value:sendmailcnf);
set_kb_item(name: "GSHB/SENDMAIL/mlocalp", value:mlocalp);
set_kb_item(name: "GSHB/SENDMAIL/lsmlocalp", value:lsmlocalp);
set_kb_item(name: "GSHB/SENDMAIL/lsstatusfiledir", value:lsstatusfiledir);
set_kb_item(name: "GSHB/SENDMAIL/lsstatusfile", value:lsstatusfile);
set_kb_item(name: "GSHB/SENDMAIL/statusfile", value:statusfile);
set_kb_item(name: "GSHB/SENDMAIL/statusfiledir", value:statusfiledir);
set_kb_item(name: "GSHB/SENDMAIL/fx", value:fx);
set_kb_item(name: "GSHB/SENDMAIL/mlocal", value:mlocal);
set_kb_item(name: "GSHB/SENDMAIL/lsforward", value:lsforward);
set_kb_item(name: "GSHB/SENDMAIL/queuedir", value:queuedir);
set_kb_item(name: "GSHB/SENDMAIL/lsqueuedir", value:lsqueuedir);
set_kb_item(name: "GSHB/SENDMAIL/lsqueue", value:lsqueue);
set_kb_item(name: "GSHB/SENDMAIL/aliases", value:aliases);
set_kb_item(name: "GSHB/SENDMAIL/aliaspath", value:aliaspath);
set_kb_item(name: "GSHB/SENDMAIL/incaliases", value:incaliases);
set_kb_item(name: "GSHB/SENDMAIL/lsaliases", value:lsaliases);
set_kb_item(name: "GSHB/SENDMAIL/lsaliasesdb", value:lsaliasesdb);

exit(0);
