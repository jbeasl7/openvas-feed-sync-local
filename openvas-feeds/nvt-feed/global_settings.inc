# SPDX-FileCopyrightText: 2004 Anonymous
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

global_var report_verbosity, log_verbosity, debug_level;

report_verbosity = 1;
debug_level = 0;
log_verbosity = 1;

__gs_opt = get_kb_item("global_settings/report_verbosity");
if (__gs_opt)
{
  if ("Normal" >< __gs_opt) report_verbosity = 1;
  else if ("Quiet" >< __gs_opt) report_verbosity = 0;
  else if ("Verbose" >< __gs_opt) report_verbosity = 2;
}

__gs_opt = get_kb_item("global_settings/log_verbosity");
if (__gs_opt)
{
  if ("Normal" >< __gs_opt) log_verbosity = 1;
  else if ("Quiet" >< __gs_opt) log_verbosity = 0;
  else if ("Verbose" >< __gs_opt) log_verbosity = 2;
  else if ("Debug" >< __gs_opt)
  {
   log_verbosity = 3;
   __gs_opt = get_kb_item("global_settings/debug_level");
   if (__gs_opt =~ '^[0-9]+$') debug_level = int(__gs_opt);
   if (debug_level <= 0) debug_level = 1;
  }
}

# a0 to a9 parameters are useless. They were added to suppress a warning
# with old NASL2 interpreters
function debug_print(level, a0, a1, a2, a3, a4, a5, a6, a7, a8, a9)
{
 local_var msg, _i, l;

 if (isnull(level)) level = 1;
 if (debug_level < level) return;
 msg = strcat(SCRIPT_NAME, '(', get_host_ip(), '): ');
 foreach _i (_FCT_ANON_ARGS) { msg = string(msg, _i); }
 l = strlen(msg);
 if (l == 0) return;
 if (msg[l-1] != '\n') msg += '\n';
 display("DEBUG: ", msg);
}

# a0 to a9 parameters are useless. They were added to suppress a warning
# with old NASL2 interpreters
function log_print(level, a0, a1, a2, a3, a4, a5, a6, a7, a8, a9)
{
 local_var msg, _i, l;

 if (isnull(level)) level = 1;
 if (debug_level <= 0 || log_verbosity < level) return;
 msg = strcat(SCRIPT_NAME, '(', get_host_ip(), '): ');
 foreach _i (_FCT_ANON_ARGS) { msg = string(msg, _i); }
 l = strlen(msg);
 if (l == 0) return;
 if (msg[l-1] != '\n') msg += '\n';
 display("LOG: ", msg);
}

GLOBAL_SETTINGS_INC = 1;
