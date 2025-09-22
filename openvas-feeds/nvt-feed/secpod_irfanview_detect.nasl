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
  script_oid("1.3.6.1.4.1.25623.1.0.900376");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2021-09-01T14:04:04+0000");
  script_tag(name:"last_modification", value:"2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)");
  script_tag(name:"creation_date", value:"2009-06-24 07:17:25 +0200 (Wed, 24 Jun 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("IrfanView Detection (Windows SMB Login)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);

  script_tag(name:"summary", value:"SMB login-based detection of IrfanView.");

  script_tag(name:"qod_type", value:"executable_version");

  exit(0);
}

include("smb_nt.inc");
include("secpod_smb_func.inc");
include("cpe.inc");
include("host_details.inc");

os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch)
  exit(0);

if("x86" >< os_arch)
  key_list = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\IrfanView");

else if("x64" >< os_arch)
  key_list = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\IrfanView",
                       "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\IrfanView64",
                       "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\IrfanView");

if(isnull(key_list))
  exit(0);

foreach key(key_list) {

  irfName = registry_get_sz(key:key, item:"DisplayName");
  irfVer = registry_get_sz(key:key, item:"DisplayVersion");
  irfPath = registry_get_sz(key:key, item:"InstallLocation");
  if(!irfPath)
    irfPath = "Unable to fetch the install location";

  if(!irfVer) {
    # nb: Keeping old logic in case of failure to get version.
    path = registry_get_sz(key:key, item:"UninstallString");
    if(path) {
      irViewPath = path - "\iv_uninstall.exe" + "\i_view32.exe";
      irfVer = GetVersionFromFile(file:irViewPath, verstr:"prod");
    }
  }

  if(irfVer) {
    set_kb_item(name:"IrfanView/Ver", value:irfVer);
    cpe = build_cpe(value:irfVer, exp:"^([0-9.]+)", base:"cpe:/a:irfanview:irfanview:");
    if(!cpe)
      cpe = "cpe:/a:irfanview:irfanview";

    if("x64" >< os_arch && "64-bit" >< irfName) {
      set_kb_item(name:"IrfanView/Ver/x64", value:irfVer);
      cpe = build_cpe(value:irfVer, exp:"^([0-9.]+)", base:"cpe:/a:irfanview:irfanview:x64:");
      if(!cpe)
        cpe = "cpe:/a:irfanview:irfanview:x64";
    }

    register_product(cpe:cpe, location:irfPath, port:0, service:"smb-login");
    log_message(data:build_detection_report(app:irfName,
                                            version:irfVer,
                                            install:irfPath,
                                            cpe:cpe,
                                            concluded:irfVer));
  }
}

exit(0);
