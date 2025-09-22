# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

# @brief This OS detection retrieves all release information it needs itself to detect Arch Linux.
#        On a successful detection the relevant info is set into the KB key and reported via
#        @ref log_message() and @ref os_register_and_report().
#
# @note It should be included in the appropriate section of gather-package-list.nasl with
#       `include("<this_files_name>")`.
#
# @note The OS detection method should be called also at the appropriate section in
#       gather-package-list.nasl.
#
# @param sock             The opened socket for the connection to the remote SSH service.
# @param port             The port for the connection to the remote SSH service.
# @param SCRIPT_DESC      The script name of the "caller" (defined within the caller itself)
# @param is_pfsense       Should be set to TRUE if the target is running pfSense as this requires
#                         some special handling.
# @param _unknown_os_info The "_unknown_os_info" variable filled in by the caller
#
# @return This function is either exiting directly on a successful detection or is returning the
#         info passed via the _unknown_os_info variable.
#
function detect_archlinux(sock, port, SCRIPT_DESC, is_pfsense, _unknown_os_info) {

  # nb: function parameters
  local_var sock, port, SCRIPT_DESC, is_pfsense, _unknown_os_info;

  # nb: variables from function body
  local_var cmd, rls, notusoskey, buf;

  if (is_pfsense)
    return _unknown_os_info;

  cmd = "cat /etc/os-release";
  rls = ssh_cmd(socket:sock, cmd:cmd, return_errors:FALSE);

  # nb: Arch Linux is a rolling release so there is no "real" version
  if (!rls || 'NAME="Arch Linux"' >!< rls) {
    _unknown_os_info += cmd + ": " + rls + '\n\n';
    return _unknown_os_info;
  }

  notusoskey = "Arch Linux";
  buf = ssh_cmd(socket:sock, cmd:"pacman -Q");

  if (buf) {
    # Each line ends with \r\n. The \r has to be filtered out.
    buf = ereg_replace(string:buf, pattern:'\r', replace:"");
    # command output contains ANSI cursor control sequences
    buf = buf - '\x1b[?25l';
    buf = buf - '\x1b[?25h';
    # Trailing white space is treated as a package with empty name and crashes scan.
    buf = chomp(buf);
    if (buf)
      register_notus(os_release:notusoskey, pkg_list:buf, rpms:FALSE);
  }

  set_kb_item(name:"ssh/login/arch_linux", value:TRUE);
  set_kb_item(name:"ssh/login/release", value:"ArchLinux");

  log_message(port:port, data:create_lsc_os_detection_report(detect_text:"Arch Linux"));
  os_register_and_report(os:"Arch Linux", cpe:"cpe:/o:archlinux:arch_linux", banner_type:"SSH login", desc:SCRIPT_DESC, runs_key:"unixoide");
  exit(0);
}
