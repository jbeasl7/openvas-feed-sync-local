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
  script_oid("1.3.6.1.4.1.25623.1.0.900025");
  script_version("2021-09-01T14:04:04+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)");
  script_tag(name:"creation_date", value:"2008-08-19 14:38:55 +0200 (Tue, 19 Aug 2008)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Microsoft Office Version Detection");

  script_tag(name:"summary", value:"Detects the installed version of Microsoft Office.

  The script logs in via smb, searches for Microsoft Office in the registry, gets
  version from the 'DisplayVersion' string and set it in the KB item.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);
  exit(0);
}

include("smb_nt.inc");
include("secpod_smb_func.inc");
include("cpe.inc");
include("host_details.inc");

TMP_OFFICE_LIST = make_list( "^(9\..*)",  "cpe:/a:microsoft:office:2000:",
                             "^(10\..*)", "cpe:/a:microsoft:office:2002:",
                             "^(11\..*)", "cpe:/a:microsoft:office:2003:",
                             "^(12\..*)", "cpe:/a:microsoft:office:2007:",
                             "^(14\..*)", "cpe:/a:microsoft:office:2010:",
                             "^(15\..*)", "cpe:/a:microsoft:office:2013:",
                             "^(16\..*)", "cpe:/a:microsoft:office:2016:");
MAX = max_index(TMP_OFFICE_LIST);
checkdupOffc = ""; # nb: To make openvas-nasl-lint happy...

if(!registry_key_exists(key:"SOFTWARE\Microsoft\Office"))
{
  if(!registry_key_exists(key:"SOFTWARE\Wow6432Node\Microsoft\Office")){
    exit(0);
  }
}

os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch){
  exit(0);
}

if("x86" >< os_arch){
  key_list = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\");
}

## Presently 64bit application is not available
else if("x64" >< os_arch)
{
  key_list =  make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\",
                        "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\");
}

foreach key (key_list)
{
  foreach item (registry_enum_keys(key:key))
  {
    MSOffName = registry_get_sz(key:key + item, item:"DisplayName");

    if(egrep(pattern:"Microsoft Office.* Viewer", string:MSOffName))
    {
      MSOffVer = registry_get_sz(key:key + item, item:"DisplayVersion");
      if(MSOffVer)
      {
        MSOffLoc= registry_get_sz(key:key + item, item:"InstallLocation");
        if(!MSOffLoc){
          MSOffLoc = "Could not find the install location from registry";
        }

          set_kb_item(name:"MS/Office/Viewer/Ver", value:MSOffVer);
          set_kb_item( name:"MS/Office/Prdts/Installed", value:TRUE );

          register_and_report_cpe( app:MSOffName, ver:MSOffVer, base:"cpe:/a:microsoft:office_word_viewer:", expr:"^([0-9.]+)", insloc:MSOffLoc );

          if("64" >< os_arch && "Wow6432Node" >!< key && "32-bit" >!< MSOffName)
          {
            set_kb_item(name:"MS/Office/Viewer64/Ver", value:MSOffVer);
            register_and_report_cpe( app:MSOffName, ver:MSOffVer, concluded:MSOffVer, base:"cpe:/a:microsoft:office_word_viewer:x64:", expr:"^([0-9.]+)", insloc:MSOffLoc );
          }
        }
        continue;
      }

      if(egrep(pattern:"Microsoft Office (2000|XP|.* Edition 2003$|[^L)].* 2007$|.* 2010$|.*2013$|.*2016)",
               string:MSOffName))
      {
        MSOffVer = registry_get_sz(key:key + item, item:"DisplayVersion");
        if(MSOffVer)
        {
          MSOffLoc = registry_get_sz(key:key + item, item:"InstallLocation");
          if(!MSOffLoc){
            MSOffLoc = "Could not find the install location from registry";
          }

          if(MSOffVer != NULL)
          {
            if (MSOffVer + ", " >< checkdupOffc){
              continue;
            }

            checkdupOffc  += MSOffVer + ", ";

            ##  Set the version for 32 bit App on 32 bit OS
            ##  Set the version for 32 bit App on 64 bit OS
            set_kb_item(name:"MS/Office/InstallPath", value:MSOffLoc);
            set_kb_item(name:"MS/Office/Ver", value:MSOffVer);
            set_kb_item( name:"MS/Office/Prdts/Installed", value:TRUE );

            for (i = 0; i < MAX-1; i = i + 2)
            {
              cpe = build_cpe(value:MSOffVer, exp:TMP_OFFICE_LIST[i], base:TMP_OFFICE_LIST[i+1]);
              if(!isnull(cpe)){
                cpe_final = cpe;
              }
            }

            if( "x64" >< os_arch && "Wow6432Node" >!< key && "32-bit" >!< MSOffName)
            {
              set_kb_item(name:"MS/Office64/Ver", value:MSOffVer);

              for (i = 0; i < MAX-1; i = i + 2)
              {
                cpe = build_cpe(value:MSOffVer, exp:TMP_OFFICE_LIST[i], base:TMP_OFFICE_LIST[i+1] + "x64:");
                if(!isnull(cpe)){
                  cpe_final = cpe;
                }
              }
            }
            register_and_report_cpe( app:MSOffName, ver:MSOffVer, concluded:MSOffVer, cpename:cpe_final, insloc:MSOffLoc );
          }
        }
        continue;
      }
    }
}
