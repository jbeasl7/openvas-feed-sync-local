# Copyright (C) 2009 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.900357");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2022-07-06T10:11:12+0000");
  script_tag(name:"last_modification", value:"2022-07-06 10:11:12 +0000 (Wed, 06 Jul 2022)");
  script_tag(name:"creation_date", value:"2009-05-29 07:35:11 +0200 (Fri, 29 May 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("NetDecision TFTP Server Version Detection");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_tag(name:"summary", value:"This script is detects installed version of NetDecision TFTP Server.");
  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("smb_nt.inc");
include("secpod_smb_func.inc");

SCRIPT_DESC = "NetDecision TFTP Server Version Detection";

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

if(!registry_key_exists(key:"SOFTWARE\NetDecision")){
  exit(0);
}

netdeciKey = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
foreach item(registry_enum_keys(key:netdeciKey))
{
  netdeciName = registry_get_sz(key:netdeciKey + item, item:"DisplayName");

  if("NetDecision" >< netdeciName)
  {
    netdeciPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion",
                                  item:"ProgramFilesDir");

    if(!netdeciPath)
      exit(0);

    netdeciPath = netdeciPath + "\NetDecision\Bin\TFTPServer.exe";
    netdeciVer = GetVersionFromFile(file:netdeciPath, verstr:"prod");

    if(netdeciVer){
      set_kb_item(name:"NetDecision/TFTP/Ver", value:netdeciVer);

      cpe = build_cpe(value: netdeciVer, exp:"^([0-9.]+)",base:"cpe:/a:netmechanica:netdecision_tftp_server:");
      if(isnull(cpe))
        cpe = "cpe:/a:netmechanica:netdecision_tftp_server";

      register_product(cpe: cpe, location: netdeciPath, port:0, service:"smb-login");
      log_message(data: build_detection_report(app: "NetDecision TFTP Server",
                                             version: netdeciVer,
                                             install: netdeciPath,
                                                 cpe: cpe,
                                           concluded: netdeciVer));
    }
    exit(0);
  }
}
exit(0);