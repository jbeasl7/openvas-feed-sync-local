# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.150306");
  script_version("2023-07-28T16:09:08+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:08 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2020-09-16 17:26:36 +0000 (Wed, 16 Sep 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Huawei Data Communication: Read current-configuration configuration section include multicast routing-enable");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "gb_huawei_vrp_network_device_consolidation.nasl");
  script_mandatory_keys("Compliance/Launch");
  script_exclude_keys("huawei/vrp/yunshan/detected");

  script_tag(name:"summary", value:"Get the sections with multicast routing-enable of the VRP
device.

Note: This script only stores information for other Policy Controls.");

  exit(0);
}

include("ssh_func.inc");

if(!get_kb_item("huawei/vrp/detected")){
  set_kb_item(name:"Policy/vrp/installed/ERROR", value:TRUE);
  exit(0);
}

if(!get_kb_item("login/SSH/success") || !sock = ssh_login_or_reuse_connection()){
  set_kb_item(name:"Policy/vrp/ssh/ERROR", value:TRUE);
  exit(0);
}

cmd = "display current-configuration | section include multicast ipv6 routing-enable";
ret = ssh_cmd(socket:sock, cmd:cmd, return_errors:TRUE, pty:TRUE, nosh:TRUE, timeout:20,
              retry:10, force_reconnect:TRUE, clear_buffer:TRUE);

if(!ret || ret == ""){
  set_kb_item(name:"Policy/vrp/current_configuration/section/include/multicast_ipv6_routing_enable/error", value:"error");
}else if(ret =~ "Error: Unrecognized command found"){
  set_kb_item(name:"Policy/vrp/current_configuration/section/include/multicast_ipv6_routing_enable/error", value:"unknown command");
}else{
  sections = split(ret, sep:"#", keep:FALSE);
  foreach section (sections){
    # skip header
    if(section !~ "multicast\s+ipv6\s+routing-enable" || section =~ "Info: It will take a long time" ||
       "section include multicast" >< section)
      continue;

    if(section =~ "^\s*multicast\s+ipv6\s+routing-enable\s*"){
      set_kb_item(name:"Policy/vrp/current_configuration/section/include/multicast_ipv6_routing_enable/public", value:TRUE);
    }else{
      name = eregmatch(string:section, pattern:"ip\s+([a-z,A-Z]*)\s*vpn-instance\s+([a-z,A-Z,:,.,0-9,_]+)");
      if(name[2]){
        set_kb_item(name:"Policy/vrp/current_configuration/section/include/multicast_ipv6_routing_enable/vpn/" + name[2], value:section);
      }
    }
  }
}

exit(0);
