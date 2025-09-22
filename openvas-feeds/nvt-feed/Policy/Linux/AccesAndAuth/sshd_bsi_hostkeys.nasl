# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.116487");
  script_version("2023-04-18T10:19:20+0000");
  script_tag(name:"last_modification", value:"2023-04-18 10:19:20 +0000 (Tue, 18 Apr 2023)");
  script_tag(name:"creation_date", value:"2023-04-11 08:00:00 +0000 (Tue, 11 Apr 2023)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Linux: BSI TR-02102-4 3.6 Server Authentication");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "read_sshd_config.nasl");
  script_mandatory_keys("Compliance/Launch");

  script_add_preference(name:"Value", type:"entry", value:"x509v3-ecdsa-sha2-nistp521,x509v3-ecdsa-sha2-nistp384,x509v3-ecdsa-sha2-nistp256,x509v3-ecdsa-sha2-1.3.132.0.10,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,ecdsa-sha2-nistp256-cert-v01@openssh.com,ecdsa-sha2-nistp384-cert-v01@openssh.com,ecdsa-sha2-nistp521-cert-v01@openssh.com", id:1);

  script_xref(name:"URL", value:"https://man7.org/linux/man-pages/man5/sshd_config.5.html");
  script_xref(name:"URL",value:"https://www.bsi.bund.de/EN/Themen/Unternehmen-und-Organisationen/Standards-und-Zertifizierung/Technische-Richtlinien/TR-nach-Thema-sortiert/tr02102/tr02102_node.html");
  script_xref(name:"URL",value:"https://ssh-comparison.quendi.de/comparison/hostkey.html");
  script_xref(name:"URL",value:"https://asyncssh.readthedocs.io/en/latest/api.html");

  script_xref(name:"Policy", value:"BSI TR-02102-4: 3.6 Server Authentication");

  script_tag(name:"summary", value:"HostKeyAlgorithms specifies the host key algorithms offered by
the server.

Note: Ensure your SSH implementation is capable of using the ciphers specified in sshd_config. This
check does not look for pgp-sign-dss as an exception.  If this cipher is used, it should have a key
length of 3000 Bits / 250 Bits to be compliant (BSI TR-02102-4 3.6)");

  exit(0);
}

include("ssh_func.inc");
include("policy_functions.inc");

cmd = "grep '^HostKeyAlgorithms' /etc/ssh/sshd_config";
title = "BSI TR-02102-4 3.6 Server Authentication";
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

    foreach hostkey(policy_build_list_from_string(str:value)){
      if(hostkey >!< default){
        compliant = "no";
        comment += hostkey + '\n';
      }
    }
  }
}

policy_reporting(result:value, default:default, compliant:compliant, fixtext:solution,
  type:test_type, test:cmd, info:comment);
policy_set_kbs(type:test_type, cmd:cmd, default:default, solution:solution, title:title,
  value:value, compliant:compliant);

exit(0);
