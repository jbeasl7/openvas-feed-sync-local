# Copyright (C) 2008 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800001");
  script_version("2021-10-01T10:02:26+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2021-10-01 10:02:26 +0000 (Fri, 01 Oct 2021)");
  script_tag(name:"creation_date", value:"2008-09-25 10:10:31 +0200 (Thu, 25 Sep 2008)");
  script_name("VMware Products Detection (Linux/Unix SSH Login)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"SSH login-based detection of various VMware Products.");

  script_tag(name:"vuldetect", value:"Currently the following VMware products are detected:

  - VMware GSX Server

  - VMware Workstation

  - VMware Server

  - VMware ESX

  - VMware Player");

  script_tag(name:"qod_type", value:"executable_version");

  exit(0);
}

include("ssh_func.inc");
include("cpe.inc");
include("host_details.inc");

sock = ssh_login_or_reuse_connection();
if(!sock)
  exit(0);

version = ssh_cmd(socket:sock, cmd:"vmware -v", timeout:120);
if("VMware GSX Server" >< version) {

  gsxVer = ereg_replace(string:version, replace:"\1", pattern:".*VMware GSX Server ([0-9].*) build.*");
  gsxVer = chomp(gsxVer);
  if(gsxVer) {
    set_kb_item(name:"VMware/GSX-Server/Linux/Ver", value:gsxVer);
    register_and_report_cpe(app:"VMware GSX Server", ver:gsxVer, base:"cpe:/a:vmware:gsx_server:", expr:"^([0-9.]+)");
  }

  gsxBuild = ereg_replace(string:version, replace:"\1", pattern:".*VMware GSX Server [0-9].* build-([0-9]+).*");
  gsxBuild = chomp(gsxBuild);
  if(gsxBuild)
    set_kb_item(name:"VMware/GSX-Server/Linux/Build", value:gsxBuild);

  set_kb_item(name:"VMware/Linux/Installed", value:TRUE);
}

else if("VMware Workstation" >< version) {

  wrkstnVer = ereg_replace(string:version, replace:"\1", pattern:".*VMware Workstation ([0-9].*) build.*");
  wrkstnVer = chomp(wrkstnVer);
  if(wrkstnVer) {
    set_kb_item(name:"VMware/Workstation/Linux/Ver", value:wrkstnVer);
    register_and_report_cpe(app:"VMware Workstation", ver:wrkstnVer, base:"cpe:/a:vmware:workstation:", expr:"^([0-9.]+)");
  }

  wrkstnBuild = ereg_replace(string:version, replace:"\1", pattern:".*VMware Workstation [0-9].* build-([0-9]+).*");
  wrkstnBuild = chomp(wrkstnBuild);
  if(wrkstnBuild)
    set_kb_item(name:"VMware/Workstation/Linux/Build", value:wrkstnBuild);

  set_kb_item(name:"VMware/Linux/Installed", value:TRUE);
}

else if("VMware Server" >< version) {

  svrVer = ereg_replace(string:version, replace:"\1", pattern:".*VMware Server ([0-9].*) build.*");
  svrVer = chomp(svrVer);
  if(svrVer) {
    set_kb_item(name:"VMware/Server/Linux/Ver", value:svrVer);
    register_and_report_cpe(app:"VMware Server", ver:svrVer, base:"cpe:/a:vmware:server:", expr:"^([0-9.]+)");
  }

  svrBuild = ereg_replace(string:version, replace:"\1", pattern:".*VMware Server [0-9].* build-([0-9]+).*");
  svrBuild = chomp(svrBuild);
  if(svrBuild)
    set_kb_item(name:"VMware/Server/Linux/Build", value:svrBuild);

  set_kb_item(name:"VMware/Linux/Installed", value:TRUE);
}

else if("VMware ESX" >< version) {

  svrVer = ereg_replace(string:version, replace:"\1", pattern:".*VMware ESX ([0-9].*) build.*");
  svrVer = chomp(svrVer);
  if(svrVer)
    set_kb_item(name:"VMware/Esx/Linux/Ver", value:svrVer);

  set_kb_item(name:"VMware/Linux/Installed", value:TRUE);
}

path = ssh_cmd(socket:sock, cmd:"which vmplayer", timeout:120);
if(path) {

  catRes = ssh_cmd(socket:sock, timeout:120, cmd:"cat /etc/vmware/config");
  if(catRes) {

    vmpVer = eregmatch(pattern:'player\\.product\\.version = "([0-9.]+)', string:catRes);
    if(vmpVer[1]) {
      set_kb_item(name:"VMware/Player/Linux/Ver", value:vmpVer[1]);
      set_kb_item(name:"VMware/Linux/Installed", value:TRUE);

      register_and_report_cpe(app:"VMware Player", ver:vmpVer[1], base:"cpe:/a:vmware:player:", expr:"^([0-9.]+)", insloc:path);
    }
  }
}

ssh_close_connection();
exit(0);