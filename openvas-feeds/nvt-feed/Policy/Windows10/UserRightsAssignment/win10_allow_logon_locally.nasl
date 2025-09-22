# Copyright (C) 2018 Greenbone Networks GmbH
#
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
  script_oid("1.3.6.1.4.1.25623.1.0.109116");
  script_version("2022-08-31T10:10:28+0000");
  script_tag(name:"last_modification", value:"2022-08-31 10:10:28 +0000 (Wed, 31 Aug 2022)");
  script_tag(name:"creation_date", value:"2018-04-30 09:56:50 +0200 (Mon, 30 Apr 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Microsoft Windows 10: Allow log on locally");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "os_detection.nasl", "policy_rsop_userprivilegeright.nasl");
  script_mandatory_keys("Compliance/Launch", "Host/runs_windows");

  script_add_preference(name:"Value", type:"entry", value:"Administrators, Users", id:1);

  script_xref(name:"Policy", value:"CIS Microsoft Windows 10 Enterprise (Release 2004) Benchmark v1.9.1: 2.2.5  (L1) Ensure 'Allow log on locally' is set to 'Administrators' and 'Users'");
  script_xref(name:"Policy", value:"CIS Controls Version 7: 4.1 Maintain Inventory of Administrative Accounts");
  script_xref(name:"Policy", value:"CIS Controls Version 7: 4.3 Ensure the Use of Dedicated Administrative Accounts");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/user-rights-assignment");

  script_tag(name:"summary", value:"This policy setting determines which users can start an
interactive session on the device. Users must have this user right to log on over a Remote Desktop
Services session that is running on a Windows-based member device or domain controller.

(C) Microsoft Corporation 2017.");

  exit(0);
}

include( "policy_functions.inc" );

title = "Allow log on locally";
solution = "Set following UI path accordingly:
Computer Configuration/Windows Settings/Security Settings/Local Policies/User Rights Assignment/" + title;
test_type = "WMI_Query";
select = "AccountList";
keyname = "SeInteractiveLogonRight";
wmi_query = "SELECT " + select + " FROM RSOP_UserPrivilegeRight WHERE UserRight = " + keyname;
default = script_get_preference( "Value", id:1 );

if(get_kb_item("policy/rsop_securitysetting/kb_smb_wmi_connectinfo/error")){
  value = "Error";
  comment = "Missing connection information to login into the host";
  compliant = "incomplete";
}else if(get_kb_item("policy/rsop_securitysetting/rsop_userprivilegeright/error")){
  value = "None";
  comment = "Can not query RSOP_UserPrivilegeRight on the host";
  compliant = "incomplete";
}else if(!value = get_kb_item("policy/rsop_securitysetting/rsop_userprivilegeright/seinteractivelogonright")){
  value = "None";
  comment = "Did not find setting on the host";
  compliant = "no";
}else{
  compliant = policy_settings_lists_match(value:value, set_points:default, sep:",");
}

policy_reporting( result:value, default:default, compliant:compliant, fixtext:solution,
  type:test_type, test:wmi_query, info:comment );
policy_set_kbs( type:test_type, cmd:wmi_query, default:default, solution:solution, title:title,
  value:value, compliant:compliant );

exit(0);
