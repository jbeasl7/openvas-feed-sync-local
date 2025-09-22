# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

# ------------------------------------------------------------------
# METADATA
# ------------------------------------------------------------------

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.130365");
  script_version("2025-09-19T15:40:40+0000");
  script_tag(name:"last_modification", value:"2025-09-19 15:40:40 +0000 (Fri, 19 Sep 2025)");
  script_tag(name:"creation_date", value:"2025-05-07 11:44:20 +0000 (Wed, 07 May 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Configure Proper Policies for OUTPUT of nftables");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "gather-package-list.nasl");
  script_mandatory_keys("Compliance/Launch", "ssh/login/euleros_eulerosvirtual_openeuler_hce");

  script_add_preference(name:"Table", type:"entry", value:"test", id:1);
  script_add_preference(name:"Chain", type:"entry", value:"output", id:2);
  script_add_preference(name:"Protocol", type:"entry", value:"tcp", id:3);
  script_add_preference(name:"Port", type:"entry", value:"22", id:4);

  script_xref(name:"Policy", value:"EulerOS Baseline: Security Committee Benchmark (v1.0.0): 3. Running and Services: 3.2 Firewall: 3.2.15 Configure Proper Policies for OUTPUT of nftables (Recommendation)");
  script_xref(name:"Policy", value:"EulerOS Virtual: Security Committee Benchmark (v1.0.0): 3. Running and Services: 3.2 Firewall: 3.2.15 Configure Proper Policies for OUTPUT of nftables (Recommendation)");
  script_xref(name:"Policy", value:"HCE Linux (Huawei Cloud EulerOS): Security Committee Benchmark (v1.0.0): 3. Running and Services: 3.2 Firewall: 3.2.15 Configure Proper Policies for OUTPUT of nftables (Recommendation)");
  script_xref(name:"Policy", value:"openEuler Baseline: Security Committee Benchmark (v1.0.0): 3. Running and Services: 3.2 Firewall: 3.2.15 Configure Proper Policies for OUTPUT of nftables (Recommendation)");

  script_tag(name:"summary", value:"There are two occasions in which a server sends outgoing
packets: 1. The local host process proactively connects to an external server, for example,
performing an HTTP access, or sending data to a log server. 2. The local host responds to the
external access to the local services.

If no policy is configured for the OUTPUT chain, all outgoing packets from the server are discarded
because the default policy is DROP.");

  exit(0);
}

include("policy_functions.inc");
include("ssh_func.inc");
include("host_details.inc");
include("policy_reporting_module.inc");

table = script_get_preference("Table");
chain = script_get_preference("Chain");
protocol = script_get_preference("Protocol");
port = script_get_preference("Port");

title = "Configure Proper Policies for OUTPUT of nftables";

solution = "Run the following command to add the ACCEPT policy to the OUTPUT chain:

# nft add rule inet <table name> <chain name> <protocol> sport <port number> accept

Example:

# nft add rule inet test output tcp sport ssh accept

Save the currently configured policy to the configuration file as follows so that it can be
automatically loaded after the system restarts.

# nft list ruleset > /etc/sysconfig/nftables.conf

Note that saving the configuration file using the preceding method will overwrite the original
configuration. You can also export the current rule to an independent file or compile a new rule in
the original file and load the rule in include mode in the /etc/sysconfig/nftables.conf
configuration file. If you use this method, avoid duplicate rules in multiple include rule files.

# nft list ruleset > /etc/nftables/new_test_rules.nft
# echo <quote>include \\<quote>/etc/nftables/new_test_rules.nft >> /etc/sysconfig/nftables.conf";

check_type = "SSH_Cmd";

action = 'Run the command in the terminal:
# nft list chain inet '+ table +' '+ chain +' 2>/dev/null | grep "'+ protocol +' sport '+ port +' accept"';

expected_value = 'The output should not be empty';

# ------------------------------------------------------------------
# CONNECTION CHECK
# ------------------------------------------------------------------

if(!get_kb_item("login/SSH/success") || !sock = ssh_login_or_reuse_connection()){

  report_ssh_error(title: title,
                   solution: solution,
                   action: action,
                   expected_value: expected_value,
                   check_type: check_type);
  exit(0);
}

# ------------------------------------------------------------------
# CHECK : Check nft list chain
# ------------------------------------------------------------------

step_cmd = 'nft list chain inet '+ table +' '+ chain +' 2>/dev/null | grep "'+ protocol +' sport '+ port +' accept"';
actual_value = ssh_cmd(socket:sock, cmd:step_cmd, return_errors:TRUE, return_linux_errors_only:TRUE);

if(actual_value){
  compliant = "yes";
  comment = "Check passed";
}else{
  compliant = "no";
  comment = "Check failed";
}

# ------------------------------------------------------------------
# REPORT
# ------------------------------------------------------------------

report_audit(action: action,
             actual_value: actual_value,
             expected_value: expected_value,
             is_compliant: compliant,
             solution: solution,
             check_type: check_type,
             title: title,
             comment: comment);

exit(0);
