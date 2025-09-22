# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108765");
  script_version("2025-05-16T05:40:21+0000");
  script_tag(name:"last_modification", value:"2025-05-16 05:40:21 +0000 (Fri, 16 May 2025)");
  script_tag(name:"creation_date", value:"2020-06-02 05:50:19 +0000 (Tue, 02 Jun 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Detection of Linux Kernel mitigation status for hardware vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("General");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/uname");
  script_exclude_keys("ssh/no_linux_shell");

  script_xref(name:"URL", value:"https://www.kernel.org/doc/html/latest/admin-guide/hw-vuln/index.html");

  script_tag(name:"summary", value:"Checks the Linux Kernel mitigation status for hardware (CPU)
  vulnerabilities.");

  script_tag(name:"qod", value:"80"); # nb: None of the existing QoD types are matching here

  exit(0);
}

include("ssh_func.inc");
include("misc_func.inc");
include("list_array_func.inc");
include("host_details.inc");

uname = get_kb_item( "ssh/login/uname" );
if( ! uname || ! eregmatch( string:uname, pattern:"^Linux ", icase:FALSE ) ) # nb: Currently only Linux Kernel supported
  exit( 0 );

if( ! sock = ssh_login_or_reuse_connection() )
  exit( 0 );

path = "/sys/devices/system/cpu/vulnerabilities/";
res = ssh_cmd( socket:sock, cmd:"ls -d " + path + "*", return_errors:TRUE, return_linux_errors_only:TRUE );
res = chomp( res );
if( ! res || ! strlen( res ) ) {
  ssh_close_connection();
  exit( 0 );
}

if( res =~ "command not found" ) { # nb: ls should be always available but still checking to avoid false positives
  ssh_close_connection();
  log_message( port:0, data:"Possible Linux system found but mandatory 'ls' command missing. Can't continue. Response: " + res );
  exit( 0 );
}

if( failed = egrep( string:res, pattern:": (Permission denied|cannot open )", icase:TRUE ) ) {

  ssh_close_connection();

  set_kb_item( name:"ssh/hw_vulns/kernel_mitigations/access_failed", value:TRUE );

  report = 'Access to the "' + path + '" sysfs interface not possible:\n\n' + chomp( failed );
  log_message( port:0, data:report );
  exit( 0 );
}

not_found = egrep( string:res, pattern:": No such file or directory", icase:TRUE );
if( not_found || ! egrep( string:res, pattern:"^" + path, icase:FALSE ) ) {

  ssh_close_connection();

  if( not_found )
    report = not_found;
  else
    report = res;

  report  = '"' + path + '" sysfs interface not available:\n\n' + chomp( report );
  report += '\n\nBased on this it is assumed that no Linux Kernel mitigations are enabled.';
  report += " If this is wrong please make the sysfs interface available for the scanning user.";

  set_kb_item( name:"ssh/hw_vulns/kernel_mitigations/sysfs_not_available", value:TRUE );
  set_kb_item( name:"ssh/hw_vulns/kernel_mitigations/sysfs_not_available/report", value:report );
  log_message( port:0, data:report );
  exit( 0 );
}

known_mitigations = make_list(
  "itlb_multihit",
  "l1tf",
  "mds",
  "meltdown",
  "mmio_stale_data",
  "retbleed",
  "spec_store_bypass",
  "spectre_v1",
  "spectre_v2", # nb: Also covering cross-thread-rsb
  "srbds",
  "tsx_async_abort",
  "spec_rstack_overflow",
  "gather_data_sampling",
  "reg_file_data_sampling",
  "indirect_target_selection"
);

info = make_array();

foreach known_mitigation( known_mitigations ) {

  # Examples gathered with:
  #
  # grep ^ /dev/null /sys/devices/system/cpu/vulnerabilities/*
  #
  # from e.g. from Kernel 6.1.0-3 on Debian bookworm/sid:
  # /sys/devices/system/cpu/vulnerabilities/itlb_multihit:KVM: Mitigation: VMX disabled
  # /sys/devices/system/cpu/vulnerabilities/l1tf:Mitigation: PTE Inversion; VMX: conditional cache flushes, SMT vulnerable
  # /sys/devices/system/cpu/vulnerabilities/mds:Mitigation: Clear CPU buffers; SMT vulnerable
  # /sys/devices/system/cpu/vulnerabilities/meltdown:Mitigation: PTI
  # /sys/devices/system/cpu/vulnerabilities/mmio_stale_data:Mitigation: Clear CPU buffers; SMT vulnerable
  # /sys/devices/system/cpu/vulnerabilities/retbleed:Mitigation: IBRS
  # /sys/devices/system/cpu/vulnerabilities/spec_store_bypass:Mitigation: Speculative Store Bypass disabled via prctl
  # /sys/devices/system/cpu/vulnerabilities/spectre_v1:Mitigation: usercopy/swapgs barriers and __user pointer sanitization
  # /sys/devices/system/cpu/vulnerabilities/spectre_v2:Mitigation: IBRS, IBPB: conditional, RSB filling, PBRSB-eIBRS: Not affected
  # /sys/devices/system/cpu/vulnerabilities/srbds:Mitigation: Microcode
  # /sys/devices/system/cpu/vulnerabilities/tsx_async_abort:Mitigation: TSX disabled
  #
  # or from Kernel 4.9.0-8 on Debian stretch:
  # /sys/devices/system/cpu/vulnerabilities/l1tf:Mitigation: PTE Inversion
  # /sys/devices/system/cpu/vulnerabilities/meltdown:Mitigation: PTI
  # /sys/devices/system/cpu/vulnerabilities/spec_store_bypass:Vulnerable
  # /sys/devices/system/cpu/vulnerabilities/spectre_v1:Mitigation: __user pointer sanitization
  # /sys/devices/system/cpu/vulnerabilities/spectre_v2:Mitigation: Full generic retpoline

  file = path + known_mitigation;
  cmd = "cat " + file;
  res = ssh_cmd( socket:sock, cmd:cmd, return_errors:TRUE, return_linux_errors_only:FALSE );
  res = chomp( res );
  if( res =~ ": No such file or directory" ) {
    # nb: The "sysfs file missing" text is used in a few VTs so make sure to update these if this
    # text here is ever changed.
    res = "sysfs file missing (" + res + ")";
    set_kb_item( name:"ssh/hw_vulns/kernel_mitigations/missing_or_vulnerable", value:TRUE );
    set_kb_item( name:"ssh/hw_vulns/kernel_mitigations/missing_or_vulnerable/" + known_mitigation, value:res );
  }

  # nb: case insensitive match because there is "Vulnerable" vs. "SMT vulnerable"
  else if( res =~ "vulnerable" ) {
    set_kb_item( name:"ssh/hw_vulns/kernel_mitigations/missing_or_vulnerable", value:TRUE );
    set_kb_item( name:"ssh/hw_vulns/kernel_mitigations/missing_or_vulnerable/" + known_mitigation, value:res );
  }

  else if( res =~ "Mitigation: .+" ) {
    set_kb_item( name:"ssh/hw_vulns/kernel_mitigations/available", value:TRUE );
    set_kb_item( name:"ssh/hw_vulns/kernel_mitigations/available/" + known_mitigation, value:res );
  }

  # e.g.:
  # Unknown: No mitigations
  else if( res =~ "^Unknown: .+" ) {
    set_kb_item( name:"ssh/hw_vulns/kernel_mitigations/unknown/" + known_mitigation, value:res );
  }

  else if( res =~ "Not affected" ) {
    set_kb_item( name:"ssh/hw_vulns/kernel_mitigations/not_affected", value:TRUE );
    set_kb_item( name:"ssh/hw_vulns/kernel_mitigations/not_affected/" + known_mitigation, value:res );
  }

  # nb: On EulerOS with a non-privileged user we're allowed to do a directly listing (the initial check) but not reading the files itself.
  else if( res =~ ": Permission denied" ) {
    set_kb_item( name:"ssh/hw_vulns/kernel_mitigations/permission_denied", value:TRUE );
    set_kb_item( name:"ssh/hw_vulns/kernel_mitigations/permission_denied/" + known_mitigation, value:res );
  }

  else {
    set_kb_item( name:"ssh/hw_vulns/kernel_mitigations/unknown", value:TRUE );
    if( ! res ) {
      res = 'Unknown: No answer received to command "' + cmd + '"';
      set_kb_item( name:"ssh/hw_vulns/kernel_mitigations/unknown/" + known_mitigation, value:"No answer received" );
    } else {
      res = 'Unknown: Unrecognized answer received to command "' + cmd + '": ' + res;
      set_kb_item( name:"ssh/hw_vulns/kernel_mitigations/unknown/" + known_mitigation, value:res );
    }
  }

  info[file] = res;
}

# nb:
# - Store link between this and all gb_hw_vuln_* Vuln-VTs
# - We don't use the host_details.inc functions in all so we need to call this directly
register_host_detail( name:"Detection of Linux Kernel mitigation status for hardware vulnerabilities", value:"cpe:/a:linux:kernel" );
register_host_detail( name:"cpe:/a:linux:kernel", value:"general/tcp" ); # the port:0 from below
register_host_detail( name:"port", value:"general/tcp" ); # the port:0 from below

report  = 'Linux Kernel mitigation status for hardware vulnerabilities:\n\n';
report += text_format_table( array:info, sep:" | ", columnheader:make_list( "sysfs file checked", "Linux Kernel status (SSH response)" ) );
report += '\n\nNotes on the "Linux Kernel status (SSH response)" column:';
report += '\n- sysfs file missing: The sysfs interface is available but the sysfs file for this specific vulnerability is missing. This means the current Linux Kernel doesn\'t know this vulnerability yet. Based on this it is assumed that it doesn\'t provide any mitigation and that the target system is vulnerable.';
report += '\n- Strings including "Mitigation:", "Not affected" or "Vulnerable" are reported directly by the Linux Kernel.';
report += '\n- All other strings are responses to various SSH commands.';

log_message( port:0, data:report );

exit( 0 );
