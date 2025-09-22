# Copyright (C) 2018 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.109074");
  script_version("2022-08-31T10:10:28+0000");
  script_tag(name:"last_modification", value:"2022-08-31 10:10:28 +0000 (Wed, 31 Aug 2022)");
  script_tag(name:"creation_date", value:"2018-04-17 09:42:28 +0200 (Tue, 17 Apr 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");
  script_name("Microsoft Office: Enable Automatic Updates");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "secpod_ms_office_detection_900025.nasl", "os_detection.nasl");
  script_add_preference(name:"Value", type:"radio", value:"1;0", id:1);
  script_mandatory_keys("Compliance/Launch", "Host/runs_windows", "MS/Office/Ver");
  script_tag(name:"summary", value:"This test checks the setting for policy 'Enable Automatic Updates'
for Microsoft Office 2013 (at least) on Windows hosts.

The setting controls whether the Office automatic updates are enabled or disabled for all Office
products installed via Click-to-Run. The setting has no effect on Office products installed via
Windows Installer.");
  exit(0);
}

include("smb_nt.inc");
include("policy_functions.inc");
include("host_details.inc");
include("version_func.inc");

target_os = policy_microsoft_windows_target_string();
target_app = "Microsoft Office";

title = "Enable Automatic Updates";
solution = "Set following UI path accordingly:
Computer Configuration/Administrative Templates/Microsoft Office VERSION/(Machine)/Updates/" + title;
type = "HKLM";
key = "software\policies\microsoft\office\OFFICE VERSION\common\officeupdate";
item = "enableautomaticupdates";
reg_path = type + "\" + key + "!" + item + "";
test_type = "RegKey";
default = script_get_preference("Value");

if(!policy_verify_win_ver()){
  results = policy_report_wrong_os(target_os:target_os);
}else if(!office_version = get_kb_item("MS/Office/Ver")){
  results = policy_report_wrong_app(target_app:target_app);
}else{
  key = str_replace(string:key, find:"OFFICE VERSION",
    replace:policy_get_major_version_app(str:office_version, sep:".", count:2, glue:"."));
  results = policy_match_exact_reg_dword(key:key, item:item, default:default);
}

value = results["value"];
comment = results["comment"];
compliant = results["compliant"];

policy_reporting(result:value, default:default, compliant:compliant, fixtext:solution,
  type:test_type, test:reg_path, info:comment);
policy_set_kbs(type:test_type, cmd:reg_path, default:default, solution:solution, title:title,
  value:value, compliant:compliant);

exit(0);