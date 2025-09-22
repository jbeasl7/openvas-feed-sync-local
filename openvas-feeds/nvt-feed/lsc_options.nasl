# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100509");
  script_version("2025-05-20T05:40:25+0000");
  script_tag(name:"last_modification", value:"2025-05-20 05:40:25 +0000 (Tue, 20 May 2025)");
  script_tag(name:"creation_date", value:"2010-02-26 12:01:21 +0100 (Fri, 26 Feb 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Options for Local Security Checks");
  script_category(ACT_SETTINGS);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Settings");

  # Use find command yes/no
  script_add_preference(name:"Also use 'find' command to search for Applications", type:"checkbox", value:"yes", id:1);
  # add -xdev to find yes/no
  script_add_preference(name:"Descend directories on other filesystem (don't add -xdev to find)", type:"checkbox", value:"yes", id:2);

  script_add_preference(name:"Enable Detection of Portable Apps on Windows", type:"checkbox", value:"no", id:3);

  script_add_preference(name:"Disable the usage of win_cmd_exec for remote commands on Windows", type:"checkbox", value:"no", id:4);

  script_add_preference(name:"Disable file search via WMI on Windows", type:"checkbox", value:"no", id:5);

  script_add_preference(name:"Report vulnerabilities of inactive Linux Kernel(s) separately (only for GOS 21.04 and older)", type:"checkbox", value:"no", id:6);

  # The value added to the -maxdepth call for find in ssh_find_file()
  script_add_preference(name:"Integer that sets the directory depth when using 'find' on unixoide systems", type:"entry", value:"12", id:7);

  # Use 'su - USER' option for ssh_cmd
  script_add_preference(name:"Use 'su - USER' option on SSH commands", type:"radio", value:"no;yes", id:8);

  # Specify user for 'su - USER' option above
  script_add_preference(name:"Use this user for 'su - USER' option on SSH commands", type:"entry", value:"", id:9);

  # nb:
  # - See comments below on the purpose of the different folders excluded here
  # - When updating this also keep in sync with other places like mentioned below
  script_add_preference(name:"Folder exclusion regex for file search on Unixoide targets", type:"entry", value:"^(/(proc|afs|dev|media|mnt|net|run|sfs|sys|tmp|udev|var/(backups|cache|lib|local|lock|log|mail|opt|run|spool|tmp)|etc/init\.d|usr/share/doc)|.*/lost\+found)", id:10);

  script_tag(name:"summary", value:"This script allows users to set some Options for Local Security
  Checks which are stored in the knowledge base and used by other tests. Description of the options:

  - Also use 'find' command to search for Applications:

  Setting this option to 'no' disables the use of the 'find' command via SSH against Unixoide
  targets. This reduces scan time but might reduce detection coverage of e.g. local installed
  applications.

  - Descend directories on other filesystem (don't add -xdev to find):

  During the scan 'find' is used to detect e.g. local installed applications via SSH on Unixoide
  targets. This command is descending on special (network-)filesystems like NFS, SMB or similar
  mounted on the target host by default. Setting this option to 'no' might reduce the scan time if
  network based filesystems are not searched for installed applications.

  - Enable Detection of Portable Apps on Windows:

  Setting this option to 'yes' enables the Detection of Portable Apps on Windows via WMI. Enabling
  this option might increase scan time as well as the load on the target host.

  - Disable the usage of win_cmd_exec for remote commands on Windows:

  Some AV solutions might block remote commands called on the remote host via a scanner internal
  'win_cmd_exe' function. Setting this option to 'yes' disables the usage of this function (as a
  workaround for issues during the scan) with the risk of lower scan coverage against Windows
  targets.

  - Disable file search via WMI on Windows:

  Various VTs are using WMI to search for files on Windows targets. Depending on the attached
  storage and its size this routine might put high load on the target and could slow down the scan.
  Setting this option to 'yes' disables the usage of this search with the risk of lower scan
  coverage against Windows targets.

  - Report vulnerabilities of inactive Linux Kernel(s) separately:

  All current package manager based Local Security Checks are reporting the same severity for active
  and inactive Linux Kernel(s). If this setting is enabled the reporting for inactive Linux
  Kernel(s) is done separately in the VT 'Report Vulnerabilities in inactive Linux Kernel(s)'
  (OID: 1.3.6.1.4.1.25623.1.0.108545).

  Please note that this functionality is currently only available for Debian (and Derivates using
  apt-get) and RPM based Distributions and needs to be considered as 'experimental'.

  - Integer that sets the directory depth when using 'find' on unixoide systems:

  A non-negative integer added as '-maxdepth' parameter to all 'find' calls used during a scan of
  unixoide systems.

  - Use 'su - USER' option on SSH commands and Use this user for 'su - USER' option on SSH commands:

  Deprecated preferences / options which will be removed in the future. Please migrate to the new
  'Elevate Privileges' feature introduced in GOS/GVM 21.04.5. See the references for more
  information.

  - Folder exclusion regex for file search on Unixoide targets:

  During the scan 'find' and/or 'locate' is used to detect e.g. local installed applications via SSH
  on Unixoide targets. This option allows to pass a regex to define which folders should be excluded
  / not searched when searching for files on such a target. Please pass 'None' to the option if you
  don't want to exclude any folders. Note: Even if 'None' is passed the '/proc' folder will be
  always excluded during the 'find' usage.");

  script_xref(name:"URL", value:"https://docs.greenbone.net/GSM-Manual/gos-22.04/en/scanning.html#creating-a-target");

  script_tag(name:"qod_type", value:"general_note");

  exit(0);
}

find_enabled         = script_get_preference("Also use 'find' command to search for Applications", id:1);
nfs_search_enabled   = script_get_preference("Descend directories on other filesystem (don't add -xdev to find)", id:2);
search_portable      = script_get_preference("Enable Detection of Portable Apps on Windows", id:3);
disable_win_cmd_exec = script_get_preference("Disable the usage of win_cmd_exec for remote commands on Windows", id:4);
disable_wmi_search   = script_get_preference("Disable file search via WMI on Windows", id:5);
kernel_overwrite     = script_get_preference("Report vulnerabilities of inactive Linux Kernel(s) separately", id:6);
find_maxdepth        = script_get_preference("Integer that sets the directory depth when using 'find' on unixoide systems", id:7);
use_su               = script_get_preference("Use 'su - USER' option on SSH commands", id:8);
su_user              = script_get_preference("Use this user for 'su - USER' option on SSH commands", id:9);
unix_search_excl     = script_get_preference("Folder exclusion regex for file search on Unixoide targets", id:10);

if( find_enabled )
  set_kb_item( name:"ssh/lsc/enable_find", value:find_enabled );

if( nfs_search_enabled )
  set_kb_item( name:"ssh/lsc/descend_ofs", value:nfs_search_enabled );

if( kernel_overwrite && "yes" >< kernel_overwrite )
  set_kb_item( name:"ssh/login/kernel_reporting_overwrite/enabled", value:TRUE );

if( search_portable && "yes" >< search_portable )
  set_kb_item( name:"win/lsc/search_portable_apps", value:TRUE );

if( disable_win_cmd_exec && "yes" >< disable_win_cmd_exec )
  set_kb_item( name:"win/lsc/disable_win_cmd_exec", value:TRUE );

if( disable_wmi_search && "yes" >< disable_wmi_search )
  set_kb_item( name:"win/lsc/disable_wmi_search", value:TRUE );

if( ! isnull( find_maxdepth ) ) {
  if( ! find_maxdepth )
    find_maxdepth = "zero";

  set_kb_item( name:"ssh/lsc/find_maxdepth", value:find_maxdepth );
}

if( use_su && "yes" >< use_su ) {

  # nb: We're using "yes" / "no" here so that we can overwrite
  # it later in gather-package-list.nasl again.
  set_kb_item( name:"ssh/lsc/use_su", value:"yes" );

  if( ! isnull( su_user ) ) {
    if( ! su_user ) {
      # Do not use 'su -' option if no user is specified
      replace_kb_item( name:"ssh/lsc/use_su", value:"no" );
    } else {
      set_kb_item( name:"ssh/lsc/su_user", value:su_user );
      log_message( port:0, data:"Deprecated 'su - USER' preferences configured which will be removed in the future. Please migrate to the new 'Elevate Privileges' feature introduced in GOS/GVM 21.04.5. See the references for more information." );
    }
  } else {
    # Do not use 'su -' option if no user is specified
    replace_kb_item( name:"ssh/lsc/use_su", value:"no" );
  }
}

if( unix_search_excl ) {
  set_kb_item( name:"ssh/lsc/search_exclude_paths", value:unix_search_excl );
} else {
  # nb:
  # - /run is excluded because it is a new storage of transient state files on at least Debian. See
  #   https://wiki.debian.org/ReleaseGoals/RunDirectory for more info
  # - /lost+found can be placed on any partition and is created by "fsck" during recovery of
  #   corrupted files. Including this folder by default doesn't make any sense as it could include a
  #   huge amount of binary data. See the following for more background info:
  #   https://tldp.org/LDP/Linux-Filesystem-Hierarchy/html/lostfound.html
  # - The "/lost\+found" is used separately to catch e.g. these:
  #   /var/lib/lost+found
  #   /var/lost+found
  #   /lost+found
  #   but NOT this:
  #   /usr/sbin/mklost+found
  # - See e.g. https://tldp.org/LDP/Linux-Filesystem-Hierarchy/html/var.html for more background
  #   info on each excluded dir in "/var". For example "/var/opt" is excluded because it is only
  #   used for "Variable data" of the packages installed to "/opt" (nb: This one shouldn't be
  #   excluded) according to:
  #   https://refspecs.linuxfoundation.org/FHS_3.0/fhs/ch05s12.html
  # - "/proc" is "very special in that it is also a virtual filesystem" and "It doesn't contain
  #   'real' files".
  #   - See e.g. https://tldp.org/LDP/Linux-Filesystem-Hierarchy/html/proc.html
  #   - The folder will be also always excluded in "ssh_find_file()" of "ssh_func.inc" when using
  #     "find" and if the exclude path is configured to 'None'
  # - Keep in sync with the default pattern in ssh_func.inc. This string is used at multiple places
  #   so that VTs calling the function from command line (via openvas-nasl) will get the same
  #   default regex
  set_kb_item( name:"ssh/lsc/search_exclude_paths", value:"^(/(proc|afs|dev|media|mnt|net|run|sfs|sys|tmp|udev|var/(backups|cache|lib|local|lock|log|mail|opt|run|spool|tmp)|etc/init\.d|usr/share/doc)|.*/lost\+found)" );
}

exit( 0 );
