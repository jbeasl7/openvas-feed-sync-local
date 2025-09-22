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
  script_oid("1.3.6.1.4.1.25623.1.0.130390");
  script_version("2025-08-21T05:40:06+0000");
  script_tag(name:"last_modification", value:"2025-08-21 05:40:06 +0000 (Thu, 21 Aug 2025)");
  script_tag(name:"creation_date", value:"2025-05-07 11:45:55 +0000 (Wed, 07 May 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Enable IMA Measurement");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "gather-package-list.nasl");
  script_mandatory_keys("Compliance/Launch", "ssh/login/euleros_eulerosvirtual_openeuler_hce");

  script_xref(name:"Policy", value:"EulerOS Baseline: Security Committee Benchmark (v1.0.0): 2. Secure Access: 2.5 Integrity: 2.5.1 Enable IMA Measurement (Recommendation)");
  script_xref(name:"Policy", value:"EulerOS Virtual: Security Committee Benchmark (v1.0.0): 2. Secure Access: 2.5 Integrity: 2.5.1 Enable IMA Measurement (Recommendation)");
  script_xref(name:"Policy", value:"HCE Linux (Huawei Cloud EulerOS): Security Committee Benchmark (v1.0.0): 2. Secure Access: 2.5 Integrity: 2.5.1 Enable IMA Measurement (Recommendation)");
  script_xref(name:"Policy", value:"openEuler Baseline: Security Committee Benchmark (v1.0.0): 2. Secure Access: 2.5 Integrity: 2.5.1 Enable IMA Measurement (Recommendation)");

  script_tag(name:"summary", value:"Integrity Measurement Architecture (IMA) is an integrity
protection function of the kernel. When IMA is enabled, integrity measurement is provided for
important system files based on user-defined policies. The measurement results can be used for
local and remote integrity attestation.

If IMA is disabled, the system can neither record the abstract of key files in real time nor
identify the tampering of file contents or attributes. Functions that protect system integrity,
such as local attestation and remote attestation (RA), depend on the digest value provided by IMA.
Therefore, these functions cannot be used, or integrity protection is incomplete.

IMA global policies need to be configured based on the specific environment. Generally, integrity
protection applies only to immutable files (such as executable files and dynamic libraries).
Improper policy configuration may cause high performance and memory overhead. You are advised to
determine whether to enable IMA and configure a correct policy based on service requirements.

Note: IMA provides only the measurement function in the global integrity protection mechanism. To
use integrity protection completely, TPM 2.0 and RA services are required. This document only
describes the measurement function of IMA and related suggestions. If the system is not integrated
with the TPM 2.0 and RA services, do not enable IMA.
IMA-measurement does not support container and VM environments, requires UEFI boot, and does not
support the legacy mode.");

  exit(0);
}

include("policy_functions.inc");
include("ssh_func.inc");
include("host_details.inc");
include("policy_reporting_module.inc");

title = "Enable IMA Measurement";

solution = '1. Set the startup parameters integrity=1, ima_appraise=off, and evm=ignore in the
/boot/efi/EFI/openEuler/grub.cfg file (ima_appraise and evm are optional).

# vim /boot/efi/EFI/openEuler/grub.cfg
        linuxefi   /vmlinuz-<kernel version> root=/dev/mapper/openeuler-root ro
resume=dev/mapper/openeuler-swap rd.lvm.lv=openeuler/root rd.lvm.lv=openeuler/swap crashkernel=512M
integrity=1 ima_appraise=off evm=ignore

2. Configure a measurement policy in either of the following ways:
Add the policy file ima-policy to the /etc/ima directory. You can customize policies in the
ima-policy file flexibly.

# vim /etc/ima/ima-policy
<ima policy lines>

Configure ima_policy=<tcb/exec_tcb&gt in the startup parameters. This mode uses the following
default policies: (The default policy measurement file has a large range. Exercise caution when
using this mode.)

# vim /boot/efi/EFI/openEuler/grub.cfg
        linuxefi   /vmlinuz-<kernel version> root=/dev/mapper/openeuler-root ro
resume=dev/mapper/openeuler-swap rd.lvm.lv=openeuler/root rd.lvm.lv=openeuler/swap crashkernel=512M
integrity=1 ima_policy=tcb';

check_type = "SSH_Cmd";

action = '1. Run the command in the terminal:
# cat /proc/cmdline | grep -E "(^| )integrity=1( |$)"

2. Run the command in the terminal:
# cat /sys/kernel/security/ima/runtime_measurements_count';

expected_value = '1. The output should contain "integrity=1"
2. The output should higher than to "1"';

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

overall_pass = FALSE;
actual_value = "";

# ------------------------------------------------------------------
# CHECK 1 :  Verify command `cat /proc/cmdline | grep integrity=1`
# ------------------------------------------------------------------

step_cmd_check_1 = 'cat /proc/cmdline | grep -E "(^| )integrity=1( |$)"';
step_res_check_1 = ssh_cmd(socket:sock, cmd:step_cmd_check_1, return_errors:TRUE, return_linux_errors_only:TRUE);
actual_value += '1. ' + step_res_check_1 + '\n';
check_result_1 = FALSE;

if(strstr(step_res_check_1, 'integrity=1')){
  check_result_1 = TRUE;
}

# ------------------------------------------------------------------
# CHECK 2 :  Verify command `cat /sys/kernel/security/ima/runtime_measurements_count`
# ------------------------------------------------------------------

step_cmd_check_2 = 'cat /sys/kernel/security/ima/runtime_measurements_count';
step_res_check_2 = ssh_cmd(socket:sock, cmd:step_cmd_check_2, return_errors:TRUE, return_linux_errors_only:TRUE);
actual_value += '2. ' + step_res_check_2 + '\n';
check_result_2 = FALSE;

if(int(step_res_check_2) > int(1)){
  check_result_2 = TRUE;
}

# ------------------------------------------------------------------
# FINAL RESULT
# ------------------------------------------------------------------
if(check_result_1 && check_result_2){
  overall_pass = TRUE;
}

if(overall_pass){
  compliant = "yes";
  comment = "All checks passed";
}else{
  compliant = "no";
  comment = "One or more checks failed";
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