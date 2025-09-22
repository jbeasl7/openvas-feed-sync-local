# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.109113");
  script_version("2024-03-19T15:34:11+0000");
  script_tag(name:"last_modification", value:"2024-03-19 15:34:11 +0000 (Tue, 19 Mar 2024)");
  script_tag(name:"creation_date", value:"2018-04-30 09:56:50 +0200 (Mon, 30 Apr 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Microsoft Windows 10: Access this computer from the network");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "os_detection.nasl", "policy_rsop_userprivilegeright.nasl");
  script_mandatory_keys("Compliance/Launch", "Host/runs_windows");

  script_add_preference(name:"Value", type:"entry", value:"Administrators, Remote Desktop Users", id:1);

  script_xref(name:"Policy", value:"CIS Microsoft Windows 10 Enterprise (Release 22H2) Benchmark v2.0.0: 2.2.2 (L1) Ensure 'Access this computer from the network' is set to 'Administrators Remote Desktop Users'");
  script_xref(name:"Policy", value:"CIS Microsoft Windows 10 Enterprise (Release 2004) Benchmark v1.9.1: 2.2.2 (L1) Ensure 'Access this computer from the network' is set to 'Administrators' and 'Remote Desktop Users' (Automated)");
  script_xref(name:"Policy", value:"CIS Controls Version 7: 9.2 Ensure Only Approved Ports Protocols and Services Are Running");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/user-rights-assignment");

  script_tag(name:"summary", value:"The Access this computer from the network policy setting
determines which users can connect to the device from the network. This capability is required by a
number of network protocols, including Server Message Block (SMB)-based protocols, NetBIOS, Common
Internet File System (CIFS), and Component Object Model Plus (COM+).

Users, devices, and service accounts gain or lose the Access this computer from network user right
by being explicitly or implicitly added or removed from a security group that has been granted this
user right. For example, a user account or a machine account may be explicitly added to a custom
security group or a built-in security group, or it may be implicitly added by Windows to a computed
security group such as Domain Users, Authenticated Users, or Enterprise Domain Controllers. By
default, user accounts and machine accounts are granted the Access this computer from network user
right when computed groups such as Authenticated Users, and for domain controllers, the Enterprise
Domain Controllers group, are defined in the default domain controllers Group Policy Object (GPO).

(C) Microsoft Corporation 2017.");

  exit(0);
}

include( "policy_functions.inc" );

title = "Access this computer from the network";
solution = "Set following UI path accordingly:
Computer Configuration/Windows Settings/Security Settings/Local Policies/User Rights Assignment/" + title;
test_type = "WMI_Query";
select = "AccountList";
keyname = "SeNetworkLogonRight";
wmi_query = "SELECT " + select + " FROM RSOP_UserPrivilegeRight WHERE UserRight = " + keyname;
default = script_get_preference( "Value", id:1 );

if(get_kb_item("policy/rsop_securitysetting/kb_smb_wmi_connectinfo/error")){
  value = "Error";
  comment = "Missing connection information to login into the host";
  compliant = "incomplete";
}else if(get_kb_item("policy/rsop_securitysetting/rsop_userprivilegeright/error")){
  value = "None";
  comment = "Can not query RSOP_UserPrivilegeRight on the host";
  compliant = "no";
}else if(!value = get_kb_item("policy/rsop_securitysetting/rsop_userprivilegeright/senetworklogonright")){
  value = "None";
  comment = "Did not find setting on the host";
  compliant = "no";
}else{
  compliant = policy_settings_lists_match(value:value, set_points:default, sep: ",");
}

policy_reporting( result:value, default:default, compliant:compliant, fixtext:solution,
  type:test_type, test:wmi_query, info:comment );
policy_set_kbs( type:test_type, cmd:wmi_query, default:default, solution:solution, title:title,
  value:value, compliant:compliant );

exit(0);
