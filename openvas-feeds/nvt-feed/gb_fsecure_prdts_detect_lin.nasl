# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800357");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2024-02-08T14:36:53+0000");
  script_tag(name:"last_modification", value:"2024-02-08 14:36:53 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2009-03-13 14:39:10 +0100 (Fri, 13 Mar 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("F-Secure Multiple Products Detection (Linux/Unix SSH Login)");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"The script detects the installed version of F-Seure Anti-Virus,
  Internet security and Internet GateKeeper.");
  exit(0);
}

include("ssh_func.inc");
include("cpe.inc");
include("host_details.inc");

SCRIPT_DESC = "F-Secure Multiple Products Version Detection (Linux)";

sock = ssh_login_or_reuse_connection();
if(!sock)
  exit(0);

fsavPaths = ssh_find_file(file_name:"/fsav$", useregex:TRUE, sock:sock);

if(fsavPaths != NULL)
{
  foreach fsavBin (fsavPaths)
  {

    fsavBin = chomp(fsavBin);
    if(!fsavBin)
      continue;

    fsavVer = ssh_get_bin_version(full_prog_name:fsavBin, sock:sock, version_argv:"--version", ver_pattern:"F-Secure (Anti-Virus )?Linux (Client |Server )?Security version ([0-9.]+) build ([0-9]+)([^0-9.]|$)?");
    fsavName = fsavVer;
    if(fsavVer[3] != NULL)
    {
      if(fsavVer[4] != NULL){
        fsavVer = fsavVer[3] + "." + fsavVer[4];
      }
      else{
        fsavVer = fsavVer[3];
      }
      if(fsavName[0] =~ "Linux Security")
      {
        set_kb_item(name:"F-Sec/Products/Lin/Installed", value:TRUE);
        set_kb_item(name:"F-Sec/AV/LnxSec/Ver", value:fsavVer);

        register_and_report_cpe(app:"F-Secure Anti Virus", ver:fsavVer, base:"cpe:/a:f-secure:f-secure_linux_security:", expr:"^([0-9]+\.[0-9]+)");
      }
      if(fsavName[0] =~ "Linux Client Security")
      {
        set_kb_item(name:"F-Sec/Products/Lin/Installed", value:TRUE);
        set_kb_item(name:"F-Sec/AV/LnxClntSec/Ver", value:fsavVer);

        register_and_report_cpe(app:"F-Secure Anti Virus Client Security", ver:fsavVer, base:"cpe:/a:f-secure:f-secure_anti-virus_linux_client_security:", expr:"^([0-9]+\.[0-9]+)");
      }
      if(fsavName[0] =~ "Linux Server Security")
      {
        set_kb_item(name:"F-Sec/Products/Lin/Installed", value:TRUE);
        set_kb_item(name:"F-Sec/AV/LnxSerSec/Ver", value:fsavVer);

        register_and_report_cpe(app:"F-Secure Server Security", ver:fsavVer, base:"cpe:/a:f-secure:f-secure_anti-virus_linux_server_security:", expr:"^([0-9]+\.[0-9]+)");

      }
      break;
    }
  }
}

fsigkPaths = ssh_find_file(file_name:"/fsigk/Makefile$", useregex:TRUE, sock:sock);
if(fsigkPaths != NULL)
{
  foreach binPath (fsigkPaths)
  {
    fsigkVer = ssh_cmd(socket:sock, timeout:120, cmd:"egrep '^VERSION' " + binPath);
    if(fsigkVer != NULL)
    {
      fsigkVer = eregmatch(pattern:"VERSION.*= ([0-9.]+)([^.0-9]|$)", string:fsigkVer);

      if(fsigkVer[1] != NULL)
      {
        buildVer = ssh_cmd(socket:sock, timeout:120, cmd:"egrep '^BUILD_NUMBER' " + binPath);

        buildVer = eregmatch(pattern:"BUILD_NUMBER.*= ([0-9]+)([^.0-9]|$)", string:buildVer);

        if(buildVer[1] != NULL){
          fsigkVer = fsigkVer[1] + "." + buildVer[1];
        }
        else{
          fsigkVer = fsigkVer[1];
        }
        set_kb_item(name:"F-Sec/Products/Lin/Installed", value:TRUE);
        set_kb_item(name:"F-Sec/IntGatekeeper/Lnx/Ver", value:fsigkVer);

        register_and_report_cpe(app:"F-Secure Internet Gate Keeper", ver:fsigkVer, base:"cpe:/a:f-secure:f-secure_internet_gatekeeper_for_linux:", expr:"^([0-9]+\.[0-9]+)");
      }
      ssh_close_connection();
      exit(0);
    }
  }
}
ssh_close_connection();
exit(0);
