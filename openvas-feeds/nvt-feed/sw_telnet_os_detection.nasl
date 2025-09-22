# SPDX-FileCopyrightText: 2015 SCHUTZWERK GmbH
# SPDX-FileCopyrightText: Reworked, improved and extended detection code and pattern since 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.111069");
  script_version("2025-09-09T14:09:45+0000");
  script_tag(name:"last_modification", value:"2025-09-09 14:09:45 +0000 (Tue, 09 Sep 2025)");
  script_tag(name:"creation_date", value:"2015-12-13 13:00:00 +0100 (Sun, 13 Dec 2015)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Operating System (OS) Detection (Telnet)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2015 SCHUTZWERK GmbH");
  script_dependencies("telnetserver_detect_type_nd_version.nasl");
  script_require_ports("Services/telnet", 23);
  script_mandatory_keys("telnet/banner/available");

  script_tag(name:"summary", value:"Telnet banner based Operating System (OS) detection.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("os_func.inc");
include("telnet_func.inc");
include("misc_func.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("dump.inc");

SCRIPT_DESC = "Operating System (OS) Detection (Telnet)";
BANNER_TYPE = "Telnet banner";

port = telnet_get_port( default:23 );
banner = telnet_get_banner( port:port );
if( ! banner || banner == "" || isnull( banner ) )
  exit( 0 );

# Too generic...
if( banner =~ "^\s*User(name)?\s*:\s*$" )
  exit( 0 );

if( "Welcome to Microsoft Telnet Service" >< banner ||
    "Georgia SoftWorks Telnet Server for Windows" >< banner ) {
  os_register_and_report( os:"Microsoft Windows", cpe:"cpe:/o:microsoft:windows", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
  exit( 0 );
}

if( "Welcome to the Windows CE Telnet Service" >< banner || "Windows CE Telnet Service cannot accept anymore concurrent users" >< banner ) {
  os_register_and_report( os:"Microsoft Windows CE", cpe:"cpe:/o:microsoft:windows_ce", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
  exit( 0 );
}

if( "FreeBSD/" >< banner && ( "(tty" >< banner || "(pts" >< banner ) ) {
  os_register_and_report( os:"FreeBSD", cpe:"cpe:/o:freebsd:freebsd", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

if( "NetBSD/" >< banner && ( "(tty" >< banner || "(pts" >< banner ) ) {
  os_register_and_report( os:"NetBSD", cpe:"cpe:/o:netbsd:netbsd", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# UPS / USV on embedded OS
if( "ManageUPSnet" >< banner ) {
  os_register_and_report( os:"Linux/Unix", cpe:"cpe:/o:linux:kernel", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# Rittal CMC-TC-PU on an embedded linux, keep this above the login: check below as some devices doesn't show that login: prompt
if( "CMC-TC-PU2" >< banner ) {
  os_register_and_report( os:"Linux/Unix", cpe:"cpe:/o:linux:kernel", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# nb:
# - Keep the pattern in sync with the one in telnetserver_detect_type_nd_version.nasl
# - At least older Cisco IOS and Cisco IOS XE versions shared the same login prompt
if( "User Access Verification" >< banner && ( "Username:" >< banner || banner =~ "Cisco" || "Password:" >< banner || "IOS" >< banner ) ) {
  os_register_and_report( os:"Cisco IOS / Cisco IOS XE", cpe:"cpe:/o:cisco:ios", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# Copyright (c) 2002 - 2012 Juniper Networks, Inc. All rights reserved.
# Copyright (c) 2002 - 2009 Trapeze Networks, Inc. All rights reserved.
# Copyright (c) 2004 - 2008 3Com Corporation. All rights reserved.
#
# Those are WLAN Controller / Access Points which are most likely running an embedded Linux/Unix.
if( banner =~ "Copyright \(c\) [0-9]+ - [0-9]+ ((Juniper|Trapeze) Networks, Inc|3Com Corporation)\. All rights reserved\." ) {
  os_register_and_report( os:"Linux/Unix", cpe:"cpe:/o:linux:kernel", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

if( "metasploitable login:" >< banner && "Warning: Never expose this VM to an untrusted network!" >< banner ) {
  os_register_and_report( os:"Ubuntu", version:"8.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

if( "SunOS" >< banner && "login:" >< banner ) {
  version = eregmatch( pattern:"SunOS ([0-9.]+)", string:banner );
  if( ! isnull( version[1] ) ) {
    os_register_and_report( os:"SunOS", version:version[1], cpe:"cpe:/o:sun:sunos", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else {
    os_register_and_report( os:"SunOS", cpe:"cpe:/o:sun:sunos", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  }
  exit( 0 );
}

if( "VxWorks login:" >< banner || "Welcome to NetLinx" >< banner ) {
  os_register_and_report( os:"Wind River VxWorks", cpe:"cpe:/o:windriver:vxworks", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

if( "Draytek login:" >< banner ) {
  os_register_and_report( os:"DrayTek Vigor Firmware", cpe:"cpe:/o:draytek:vigor_firmware", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# Nexus 5000 Switch
# Nexus 3000 Switch
if( banner =~ "^Nexus ([0-9]+) Switch" ) {
  os_register_and_report( os:"Cisco NX-OS", cpe:"cpe:/o:cisco:nx-os", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

if( "Debian GNU/Linux" >< banner ) {
  version = eregmatch( pattern:"Debian GNU/Linux ([0-9.]+)", string:banner );
  if( ! isnull( version[1] ) ) {
    os_register_and_report( os:"Debian GNU/Linux", version:version[1], cpe:"cpe:/o:debian:debian_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else {
      if( "lenny" >< banner ) {
        os_register_and_report( os:"Debian GNU/Linux", version:"5.0", cpe:"cpe:/o:debian:debian_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "squeeze" >< banner ) {
        os_register_and_report( os:"Debian GNU/Linux", version:"6.0", cpe:"cpe:/o:debian:debian_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      # nb: Starting with Wheezy (7.x) we have minor releases within the version so we don't use an exact version like 7.0 as we can't differ between the OS in the banner here
      } else if( "wheezy" >< banner ) {
        os_register_and_report( os:"Debian GNU/Linux", version:"7", cpe:"cpe:/o:debian:debian_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "jessie" >< banner ) {
        os_register_and_report( os:"Debian GNU/Linux", version:"8", cpe:"cpe:/o:debian:debian_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else {
        os_register_and_report( os:"Debian GNU/Linux", cpe:"cpe:/o:debian:debian_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      }
  }
  exit( 0 );
}

if( "Ubuntu" >< banner ) {
  os_register_and_report( os:"Ubuntu", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

if( "CentOS release" >< banner ) {
  os_register_and_report( os:"CentOS", cpe:"cpe:/o:centos:centos", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

if( "Fedora release" >< banner ) {
  os_register_and_report( os:"Fedora", cpe:"cpe:/o:fedoraproject:fedora", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

if( "Fedora Core release" >< banner ) {
  os_register_and_report( os:"Fedora Core", cpe:"cpe:/o:fedoraproject:fedora_core", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

if( "Red Hat Enterprise Linux" >< banner ) {
  version = eregmatch( pattern:"Red Hat Enterprise Linux (Server|ES|AS|Client) release ([0-9.]+)", string:banner );
  if( ! isnull( version[2] ) ) {
    os_register_and_report( os:"Red Hat Enterprise Linux " + version[1], version:version[2], cpe:"cpe:/o:redhat:enterprise_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else {
    os_register_and_report( os:"Red Hat Enterprise Linux", cpe:"cpe:/o:redhat:enterprise_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  }
  exit( 0 );
}

if( "Red Hat Linux release" >< banner ) {
  os_register_and_report( os:"Redhat Linux", cpe:"cpe:/o:redhat:linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

if( "-gentoo-" >< banner ) {
  os_register_and_report( os:"Gentoo", cpe:"cpe:/o:gentoo:linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# nb: Needs to be before the "SuSE Linux" detection below
# Welcome to SUSE Linux Enterprise Server 12 SP4  (x86_64) - Kernel 4.12.14-94.41-default (2).
# Welcome to SUSE Linux Enterprise Server 11 SP3  (x86_64) - Kernel 3.0.76-0.11-default (9).
# Welcome to SUSE Linux Enterprise Server 11 (i586) - Kernel 2.6.27.19-5-pae (11).
# Welcome to SUSE Linux Enterprise Server 10 SP4  (i586) - Kernel 2.6.16.60-0.85.1-bigsmp (1).
# Welcome to SUSE Linux Enterprise Server 10 SP2 (i586) - Kernel 2.6.16.60-0.21-smp (5).
# Welcome to SUSE Linux Enterprise Server 10 SP2 (x86_64) - Kernel 2.6.16.60-0.21-smp (4).
# Welcome to SUSE Linux Enterprise Server 10 (i586) - Kernel 2.6.16.21-0.8-bigsmp (0).
# Welcome to SUSE LINUX Enterprise Server 9 (i586) - Kernel 2.6.5-7.97-smp (2).
# Welcome to SUSE Linux Enterprise Server for SAP Applications 12 SP3  (x86_64) - Kernel 4.4.73-7-default (2).
if( banner =~ "Welcome to SUSE Linux Enterprise Server" ) {

  version = eregmatch( pattern:"Welcome to SUSE Linux Enterprise Server( for SAP Applications)? ([0-9.]+) (SP[0-9]+)?", string:banner, icase:TRUE );
  if( ! isnull( version[2] ) ) {
    if( ! isnull( version[3] ) )
      os_register_and_report( os:"SUSE Linux Enterprise Server", version:version[2], patch:version[3], cpe:"cpe:/o:suse:linux_enterprise_server", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    else
      os_register_and_report( os:"SUSE Linux Enterprise Server", version:version[2], cpe:"cpe:/o:suse:linux_enterprise_server", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else {
    os_register_and_report( os:"SUSE Linux Enterprise Server", cpe:"cpe:/o:suse:linux_enterprise_server", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  }
  exit( 0 );
}

# Welcome to SuSE Linux 6.4 (i386) - Kernel 2.4.17 (0).
# Welcome to SUSE Linux
# nb: Needs to be after the "SLES" detection above
if( banner =~ "Welcome to SUSE Linux" ) {
  version = eregmatch( pattern:"Welcome to SuSE Linux ([0-9.]+)", string:banner, icase:TRUE );
  if( ! isnull( version[1] ) ) {
    os_register_and_report( os:"SUSE Linux", version:version[1], cpe:"cpe:/o:novell:suse_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else {
    os_register_and_report( os:"SUSE Linux", cpe:"cpe:/o:novell:suse_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  }
  exit( 0 );
}

if( "Welcome to openSUSE Leap" >< banner ) {
  version = eregmatch( pattern:"Welcome to openSUSE Leap ([0-9.]+)", string:banner );
  if( ! isnull( version[1] ) ) {
    os_register_and_report( os:"openSUSE Leap", version:version[1], cpe:"cpe:/o:opensuse_project:leap", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else {
    os_register_and_report( os:"openSUSE Leap", cpe:"cpe:/o:opensuse_project:leap", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  }
  exit( 0 );
}

if( "Welcome to openSUSE" >< banner ) {
  version = eregmatch( pattern:"Welcome to openSUSE ([0-9.]+)", string:banner );
  if( ! isnull( version[1] ) ) {
    os_register_and_report( os:"openSUSE", version:version[1], cpe:"cpe:/o:novell:opensuse", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else {
    os_register_and_report( os:"openSUSE", cpe:"cpe:/o:novell:opensuse", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  }
  exit( 0 );
}

# nb: More detailed OS Detection covered in gb_netapp_data_ontap_consolidation.nasl
if( banner =~ '^\r\n\r\nData ONTAP' ) {
  os_register_and_report( os:"NetApp Data ONTAP", cpe:"cpe:/o:netapp:data_ontap", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# nb: More detailed OS Detection covered in gsf/gb_synetica_datastream_devices_telnet_detect.nasl
if( "Welcome to the DataStream " >< banner ) {
  mod = eregmatch( pattern:"Welcome to the DataStream\s*([^- ]+)", string:banner );
  if( ! isnull( mod[1] ) ) {
    cpe_model = str_replace( string:tolower( mod[1] ), find:" ", replace:"_" );
    os_register_and_report( os:"Synetica DataStream - " + mod[1] + " Firmware", cpe:"cpe:/o:synetica:datastream_" + cpe_model + "_firmware", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else {
    os_register_and_report( os:"Synetica DataStream - Unknown Model Firmware", cpe:"cpe:/o:synetica:datastream_unknown_model_firmware", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  }
  exit( 0 );
}

# Grandstream GXP2124 Command Shell Copyright 2011
# Grandstream GXP2000 Command Shell
# Grandstream GXP1405 Command Shell Copyright 2011
# Grandstream GXP1200 Command Shell
#
# nb: More detailed detection in gb_grandstream_gxp_telnet_detect.nasl
if( "Grandstream GXP" >< banner ) {
  os_register_and_report( os:"Grandstream GXP Firmware", cpe:"cpe:/o:grandstream:gxp_firmware", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# nb: More detailed detection in gb_zhone_znid_gpon_telnet_detect.nasl
if( "Model: ZNID-GPON" >< banner) {
  os_register_and_report( os:"ZHONE ZNID GPON Firmware", cpe:"cpe:/o:dasanzhone:znid_firmware", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

if( "Warning: Telnet is not a secure protocol, and it is recommended to use Stelnet." >< banner || ( "Login authentication" >< banner && "Username:" >< banner ) ) {
  os_register_and_report( os:"Huawei Unknown Model Versatile Routing Platform (VRP) network device Firmware", cpe:"cpe:/o:huawei:vrp_firmware", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# nb: More detailed detection in gb_brocade_fabricos_telnet_detect.nasl
if( "Fabric OS" >< banner ) {
  os_register_and_report( os:"Brocade Fabric OS", cpe:"cpe:/o:broadcom:fabric_operating_system", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

if( "geneko login:" >< banner ) {
  os_register_and_report( os:"Geneko Router Firmware", cpe:"cpe:/o:geneko:router_firmware", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# nb: More detailed detection in gsf/gb_zyxel_usg_telnet_detect.nasl
if( "Welcome to ZyWALL USG" >< banner ) {
  os_register_and_report( os:"Zyxel USG Firmware", cpe:"cpe:/o:zyxel:usg_firmware", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# Linux 2.6.15.7-elinos-249 (xlweb) (13)
# xlweb login:
if( "xlweb login:" >< banner ) {
  os_register_and_report( os:"Honeywell Excel Web Controller Firmware", cpe:"cpe:/o:honeywell:xl_web_ii_controller", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# (Cisco Controller)
# User: Raw mode will not be supported, Closing connection.
#
# User:
if( "(Cisco Controller)" >< banner ) {
  os_register_and_report( os:"Cisco Wireless LAN Controller Firmware", cpe:"cpe:/o:cisco:wireless_lan_controller", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# nb: More detailed detection in gsf/gb_fortinet_fortiadc_telnet_detect.nasl
if( banner =~ "FortiADC[^ ]* login:" ) {
  os_register_and_report( os:"Fortinet FortiOS", cpe:"cpe:/o:fortinet:fortios", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# nb: More detailed detection covered in gb_moxa_miineport_telnet_detect.nasl
if( banner =~ "Model name\s*:\s*MiiNePort " ) {
  os_register_and_report( os:"Moxa MiiNePort Firmware", cpe:"cpe:/o:moxa:miineport_firmware", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# nb: More detailed detection covered in gsf/gb_moxa_oncell_telnet_detect.nasl
if( banner =~ "OnCell G[0-9]{4}" ) {
  os_register_and_report( os:"Moxa OnCell Firmware", cpe:"cpe:/o:moxa:oncell_firmware", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

if( banner =~ "telnet session telnet[0-9]+ on /dev/ptyb[0-9]+" ) {
  os_register_and_report( os:"Extreme ExtremeXOS (EXOS)", cpe:"cpe:/o:extremenetworks:exos", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# TANDBERG Codec Release F9.1.1 PAL
if( concl = egrep( string:banner, pattern:"TANDBERG Codec Release", icase:TRUE ) ) {
  os_register_and_report( os:"Tandberg Device Firmware", cpe:"cpe:/o:tandberg:device_firmware", banner_type:BANNER_TYPE, port:port, banner:chomp( concl ), desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# e.g.:
#
# MINI-LINK 6600  Command Line Interface
#
# or:
#
# \r\r\n\r\nCLI master busy. Only one session allowed.\r\n\r\nPlease try again later.\r\n\r\n
#
# nb: Keep the pattern in sync with the ones in:
# - telnetserver_detect_type_nd_version.nasl
# - gsf/gb_ericsson_mini-link_telnet_detect.nasl
#
if( concl = egrep( string:banner, pattern:"(MINI-LINK.+Command Line Interface|CLI master busy\. Only one session allowed\..*Please try again later\.)", icase:FALSE ) ) {
  os_register_and_report( os:"Ericsson MINI-LINK Device Firmware", cpe:"cpe:/o:ericsson:mini_link_device_firmware", banner_type:BANNER_TYPE, port:port, banner:chomp( concl ), desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# Too generic, e.g.:
#
# (none) login:
# login:
# Login:
# host login:
if( eregmatch( string:banner, pattern:'^\r\n(\\(none\\) |host )?login: $', icase:TRUE ) )
  exit( 0 );

# Too generic as well and only includes the hostname, e.g.:
#
# hostname login:
#
# nb: This approach was done because there might be other devices like e.g. "VxWorks login:"
# we could miss if we're generally excluding any string in front of the "login:".
hosts = create_hostname_parts_list();
ip = get_host_ip(); # nb: create_hostname_parts_list() doesn't add the IP to the returned list.

# nb: No need to check for an empty "hosts" string here (create_hostname_parts_list() could return
# an empty list) as make_list() seems to be able to handle this.
hosts = make_list( hosts, ip );
pattern = '^\r\n(';
foreach host( hosts )
  pattern += host + '|';

pattern = ereg_replace( string:pattern, pattern:"\|$", replace:"" );
pattern += ') login: $';
pattern = str_replace( string:pattern, find:".", replace:"\." );
if( eregmatch( string:banner, pattern:pattern, icase:TRUE ) )
  exit( 0 );

# Seen on e.g. EulerOS. There might be others Distros using the same so we're ignoring this for now...
#
# Authorized users only. All activities may be monitored and reported.
# hostname login:
#
if( eregmatch( string:banner, pattern:'^\r\nAuthorized users only\\. All activities may be monitored and reported\\.\r\n[^ ]+ login: $', icase:FALSE ) )
  exit( 0 );

# Seen on e.g. NetApp Data ONTAP
if( banner == '\r\nToo many users logged in!  Please try again later.\r\n' )
  exit( 0 );

# Java and thus cross-platform
if( banner =~ "JAMES Remote Administration Tool" )
  exit( 0 );

# There are plenty of services available which are responding / reporting
# a telnet banner even if those are no telnet services. Only continue with
# the reporting of an unknown OS if we actually got a login/password prompt
# related to a Telnet service.
if( telnet_has_login_prompt( data:banner ) )
  os_register_unknown_banner( banner:banner, banner_type_name:BANNER_TYPE, banner_type_short:"telnet_banner", port:port );

exit( 0 );
