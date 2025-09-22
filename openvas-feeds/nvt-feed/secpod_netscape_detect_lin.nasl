# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900394");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2024-02-08T14:36:53+0000");
  script_tag(name:"last_modification", value:"2024-02-08 14:36:53 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2009-07-29 08:37:44 +0200 (Wed, 29 Jul 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Netscape Detection (Linux/Unix SSH Login)");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"This script detects the installed version of Netscape browser.");
  exit(0);
}

include("ssh_func.inc");
include("cpe.inc");
include("host_details.inc");

SCRIPT_DESC = "Netscape Version Detection (Linux)";

scape_sock = ssh_login_or_reuse_connection();
if(!scape_sock)
  exit(0);

netflag = 1;
scapePaths = ssh_find_file(file_name:"/netscape/netscape$", useregex:TRUE, sock:scape_sock);
foreach scapeBin (scapePaths)
{

  scapeBin = chomp(scapeBin);
  if(!scapeBin)
    continue;

  scapeVer = ssh_get_bin_version(full_prog_name:scapeBin, sock:scape_sock, version_argv:"-version", ver_pattern:"Netscape[0-9]\/([0-9.]+)(, build ([0-9]+))?");
  if(scapeVer == NULL){
    netflag = 0;
  }
}

if(netflag == 0)
{
  scapePaths = ssh_find_file(file_name:"/netscape/install\.log$", useregex:TRUE, sock:scape_sock);
  foreach scapeBin (scapePaths) {

    scapeBin = chomp(scapeBin);
    if(!scapeBin)
      continue;

    scapeVer = ssh_get_bin_version(full_prog_name:"cat", sock:scape_sock, version_argv:scapeBin, ver_pattern:"Netscape([a-zA-Z (/]+)?([0-9]\.[0-9.]+)");
  }
  if(scapeVer == NULL){
    exit(0);
  }
}

if("Netscape" >< scapeVer)
{
  if(scapeVer[1] =~ "^[0-9][0-9.]+")
  {
    if(scapeVer[3] =~ "^[0-9][0-9]+")
      ver = scapeVer[1] + "." + scapeVer[3];
    else
      ver = scapeVer[1];
  }
  else if(scapeVer[2] =~ "^[0-9][0-9.]+")
    ver = scapeVer[2];
  if(ver != NULL){
    set_kb_item(name:"Netscape/Linux/Ver", value:ver);
    log_message(data:"Netscape version " + ver + " was detected on the host");

    cpe = build_cpe(value:ver, exp:"^([0-9]+)", base:"cpe:/a:netscape:navigator:");
    if(!isnull(cpe))
      register_host_detail(name:"App", value:cpe, desc:SCRIPT_DESC);
  }
}
