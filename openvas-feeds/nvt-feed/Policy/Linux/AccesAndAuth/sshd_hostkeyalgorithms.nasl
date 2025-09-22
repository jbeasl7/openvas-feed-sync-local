# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.150559");
  script_version("2022-08-31T10:10:28+0000");
  script_tag(name:"last_modification", value:"2022-08-31 10:10:28 +0000 (Wed, 31 Aug 2022)");
  script_tag(name:"creation_date", value:"2021-01-15 13:47:26 +0000 (Fri, 15 Jan 2021)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Linux: SSH HostKeyAlgorithms");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "read_sshd_config.nasl");
  script_mandatory_keys("Compliance/Launch");

  script_add_preference(name:"Value", type:"entry", value:"pgp-sign-rsa,pgp-sign-dss,ecdsa-sha2-*,x509v3-rsa2048-sha256,x509v3-ecdsa-sha2-*", id:1);

  script_xref(name:"URL", value:"https://linux.die.net/man/5/sshd_config");

  script_tag(name:"summary", value:"HostKeyAlgorithms specifies the host key algorithms that the client wants to
  use in order of preference");

  exit(0);
}

include("ssh_func.inc");
include("policy_functions.inc");

cmd = "grep '^HostKeyAlgorithms' /etc/ssh/sshd_config";
title = "SSH HostKeyAlgorithms";
solution = "Edit /etc/ssh/sshd_config";
test_type = "SSH_Cmd";
default = script_get_preference("Value", id:1);

if(get_kb_item("Policy/linux/sshd_config/ERROR")){
  value = "Error";
  compliant = "incomplete";
  comment = "Could not read /etc/ssh/sshd_config";
}else{
  value = get_kb_item("Policy/linux/sshd_config/hostkeyalgorithms");
  if(!value){
    value = "Error";
    compliant = "incomplete";
    comment = "Could not retrieve supported HostKeyAlgorithms from /etc/ssh/sshd_config";
  }else{
    compliant = "yes";
    default_list = policy_build_list_from_string(str:default);

    foreach algorithm(policy_build_list_from_string(str:value)){
      allowed = FALSE;
      foreach default_alg(default_list){
        if(!egrep(string:algorithm, pattern:default_alg))
          continue;

        allowed = TRUE;
      }

      if(!allowed){
        compliant = "no";
        comment += algorithm + '\n';
      }
    }
  }
}

policy_reporting(result:value, default:default, compliant:compliant, fixtext:solution,
  type:test_type, test:cmd, info:comment);
policy_set_kbs(type:test_type, cmd:cmd, default:default, solution:solution, title:title,
  value:value, compliant:compliant);

exit(0);
