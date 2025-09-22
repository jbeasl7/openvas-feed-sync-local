# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.96087");
  script_version("2025-01-22T05:38:11+0000");
  script_tag(name:"last_modification", value:"2025-01-22 05:38:11 +0000 (Wed, 22 Jan 2025)");
  script_tag(name:"creation_date", value:"2010-06-21 10:39:50 +0200 (Mon, 21 Jun 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Test System if cryptsetup is installed and the SWAP Partition encrypted");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("IT-Grundschutz");
  script_dependencies("compliance_tests.nasl", "gather-package-list.nasl", "smb_nativelanman.nasl", "netbios_name_get.nasl");
  script_mandatory_keys("Compliance/Launch/GSHB");

  script_tag(name:"summary", value:"Test System if cryptsetup is installed and the SWAP Partition is
  encrypted.");

  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("ssh_func.inc");
include("misc_func.inc");
include("port_service_func.inc");
include("smb_nt.inc");

port = get_preference("auth_port_ssh");
if(!port)
  port = ssh_get_port(default:22, ignore_unscanned:TRUE);

sock = ssh_login_or_reuse_connection();
if(!sock) {
  error = ssh_get_error();
  if (!error) error = "No SSH Port or Connection!";
  log_message(port:port, data:error);

  set_kb_item(name: "GSHB/cryptsetup/inst", value:"error");
#  set_kb_item(name: "GSHB/cryptsetup/cryptdisks", value:"error");
#  set_kb_item(name: "GSHB/cryptsetup/crypttab", value:"error");
  set_kb_item(name: "GSHB/cryptsetup/fstab", value:"error");
  set_kb_item(name: "GSHB/cryptsetup/log", value:error);
  exit(0);
}
SAMBA = kb_smb_is_samba();
SSHUNAME = get_kb_item("ssh/login/uname");

if (SAMBA || (SSHUNAME && ("command not found" >!< SSHUNAME && "CYGWIN" >!< SSHUNAME))){
  rpms = get_kb_item("ssh/login/packages");

  if (rpms){
    pkg1 = "cryptsetup";
    pat1 = string("ii  (", pkg1, ") +([0-9]:)?([^ ]+)");
    desc1 = eregmatch(pattern:pat1, string:rpms);

  }else{

    rpms = get_kb_item("ssh/login/rpms");
    tmp = split(rpms, keep:0);
    if (max_index(tmp) <= 1)rpms = ereg_replace(string:rpms, pattern:";", replace:'\n');
    pkg1 = "cryptsetup";
    pat1 = string("(", pkg1, ")~([0-9a-zA-Z/.-_/+]+)~([0-9a-zA-Z/.-_]+)");
    desc1 = eregmatch(pattern:pat1, string:rpms);
  }

  if (desc1) cryptsetupinst = "yes";
  else cryptsetupinst = "no";

  if (desc1){
    cryptdisks = ssh_cmd(socket:sock, cmd:"cat /etc/default/cryptdisks");
    crypttab = ssh_cmd(socket:sock, cmd:"cat /etc/crypttab");
    fstab = ssh_cmd(socket:sock, cmd:"grep -v '^#' /etc/fstab");

    if (cryptdisks =~ ".*(Datei oder Verzeichnis nicht gefunden|No such file or directory).*") cryptdisks = "none";
    if (crypttab =~ ".*(Datei oder Verzeichnis nicht gefunden|No such file or directory).*") crypttab = "none";
    if (fstab =~ ".*(Datei oder Verzeichnis nicht gefunden|No such file or directory).*") cryptdisks = "none";

    if (cryptdisks != "none"){
      val1 = egrep(string:cryptdisks, pattern:"CRYPTDISKS_ENABLE=Yes", icase:0);
      if (val1) cryptdisks = "yes";
      else cryptdisks = "no";
    }
    if (cryptdisks != "none" && cryptdisks == "yes" && crypttab != "none"){
      val2 = egrep(string:crypttab, pattern:"swap", icase:0);
      if (val2){
        tmp = ereg_replace(string:val2, pattern:" ", replace:"", icase:0);
        tmp = ereg_replace(string:tmp, pattern:'\t', replace:"", icase:0);
        tmp = split(tmp, sep:"/", keep:0);
        crypttab = tmp[0];
      }
      else crypttab = "no";
    }
    else crypttab = "no";
    if (cryptdisks != "none" && cryptdisks == "yes" && crypttab != "none" && crypttab != "no" && fstab != "none"){
      Lst = split(fstab, keep:0);
      value =  ".*/dev/mapper/" + crypttab + ".*swap.*";
      for(i=0; i<max_index(Lst); i++){
         if (ereg(string:Lst[i], pattern:value, icase:0))val3 += Lst[i] +'\n';
      }
      if (val3) fstab = val3;
      else fstab = "no";
    }
    else fstab = "no";
  }
}
else{
  set_kb_item(name: "GSHB/cryptsetup/inst", value:"windows");
  set_kb_item(name: "GSHB/cryptsetup/cryptdisks", value:"windows");
  set_kb_item(name: "GSHB/cryptsetup/crypttab", value:"windows");
  set_kb_item(name: "GSHB/cryptsetup/fstab", value:"windows");
}

if (!cryptdisks)cryptdisks = "none";
if (!crypttab)crypttab = "none";
if (!fstab)fstab = "none";

set_kb_item(name: "GSHB/cryptsetup/inst", value:cryptsetupinst);
#set_kb_item(name: "GSHB/cryptsetup/cryptdisks", value:cryptdisks);
#set_kb_item(name: "GSHB/cryptsetup/crypttab", value:crypttab);
set_kb_item(name: "GSHB/cryptsetup/fstab", value:fstab);

exit(0);
