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
  script_oid("1.3.6.1.4.1.25623.1.0.130324");
  script_version("2025-09-22T07:08:28+0000");
  script_tag(name:"last_modification", value:"2025-09-22 07:08:28 +0000 (Mon, 22 Sep 2025)");
  script_tag(name:"creation_date", value:"2025-05-07 11:44:19 +0000 (Wed, 07 May 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Configure a Proper Number of Concurrent Unauthenticated SSH Connections");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "gather-package-list.nasl");
  script_mandatory_keys("Compliance/Launch", "ssh/login/euleros_eulerosvirtual_openeuler_hce");

  script_add_preference(name:"Fields", type:"entry", value:"10:30:60", id:1);

  script_xref(name:"Policy", value:"EulerOS Baseline: Security Committee Benchmark (v1.0.0): 3. Running and Services: 3.3 SSH: 3.3.12 Configure a Proper Number of Concurrent Unauthenticated SSH Connections (Recommendation)");
  script_xref(name:"Policy", value:"EulerOS Virtual: Security Committee Benchmark (v1.0.0): 3. Running and Services: 3.3 SSH: 3.3.12 Configure a Proper Number of Concurrent Unauthenticated SSH Connections (Recommendation)");
  script_xref(name:"Policy", value:"HCE Linux (Huawei Cloud EulerOS): Security Committee Benchmark (v1.0.0): 3. Running and Services: 3.3 SSH: 3.3.12 Configure a Proper Number of Concurrent Unauthenticated SSH Connections (Recommendation)");
  script_xref(name:"Policy", value:"openEuler Baseline: Security Committee Benchmark (v1.0.0): 3. Running and Services: 3.3 SSH: 3.3.12 Configure a Proper Number of Concurrent Unauthenticated SSH Connections (Recommendation)");

  script_tag(name:"summary", value:"Without knowing the password, an attacker can set up a large
number of concurrent connections that have not been authenticated to consume system resources.

The number of concurrent unauthenticated SSH connections is not configured in openEuler by default.
You are advised to configure the upper limit based on the actual scenario.");

  exit(0);
}

include("policy_functions.inc");
include("ssh_func.inc");
include("host_details.inc");
include("policy_reporting_module.inc");

fields = script_get_preference("Fields");

title = "Configure a Proper Number of Concurrent Unauthenticated SSH Connections";

solution = "Open the /etc/ssh/sshd_config file and configure the maxstartups field.

The value contains three fields separated by colons (:). The first and last fields indicate the
lower and upper limits of the number of connections, respectively. The middle field indicates the
percentage of discarded connections.

# vim /etc/ssh/sshd_config
maxstartups 10:30:60

When the number of unauthenticated connections reaches 10, 30% of the connection requests are
discarded. When the number of unauthenticated connections reaches 60, all new connections are
rejected.

Restart the sshd service for the setting to take effect.

# systemctl restart sshd";

check_type = "SSH_Cmd";

action = 'Run the command in the terminal:
# grep -iE "^\\s*MaxStartups\\s+" '+ fields +' /etc/ssh/sshd_config 2>/dev/null';

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
# CHECK : Check MaxStartups in sshd_config
# ------------------------------------------------------------------

step_cmd = 'grep -iE "^\\s*MaxStartups\\s+" '+ fields +' /etc/ssh/sshd_config 2>/dev/null';
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
