# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105355");
  script_version("2025-07-15T05:43:28+0000");
  script_tag(name:"last_modification", value:"2025-07-15 05:43:28 +0000 (Tue, 15 Jul 2025)");
  script_tag(name:"creation_date", value:"2015-09-15 15:57:03 +0200 (Tue, 15 Sep 2015)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Operating System (OS) Detection (FTP)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/banner/available");

  script_tag(name:"summary", value:"FTP banner based Operating System (OS) detection.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("os_func.inc");
include("ftp_func.inc");
include("port_service_func.inc");

SCRIPT_DESC = "Operating System (OS) Detection (FTP)";
BANNER_TYPE = "FTP banner";

port   = ftp_get_port( default:21 );
banner = ftp_get_banner( port:port );
banner = chomp( banner );

if( ! banner || banner == "" || isnull( banner ) )
  exit( 0 );

if( banner =~ "CP ([0-9\-]+) (IT )?FTP-Server V([0-9.]+) ready for new user" )
  exit( 0 ); # Covered by gb_simatic_cp_ftp_detect.nasl

if( banner == "220 FTP server ready" || banner == "220 FTP server ready." )
  exit( 0 );

if( " FTP server (MikroTik " >< banner )
  exit( 0 ); # Already covered by gb_mikrotik_router_routeros_consolidation.nasl

# Default welcome messages on some FTP servers
if( banner == "220 Welcome message" ||
    banner == "220 Service ready for new user." )
  exit( 0 );

# Some broken FTP server
if( "500 OOPS: could not bind listening IPv4 socket" >< banner )
  exit( 0 );

# nb: More detailed OS Detection covered in gb_netapp_data_ontap_consolidation.nasl
if( "FTP server (Data ONTAP" >< banner ) {
  os_register_and_report( os:"NetApp Data ONTAP", cpe:"cpe:/o:netapp:data_ontap", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# 220 VxWorks FTP server (VxWorks 5.3.1 - Secure NetLinx version (1.0)) ready.
# 220 VxWorks (VxWorks5.4.2) FTP server ready
# 220 VxWorks (5.4) FTP server ready
# 220 VxWorks FTP server (VxWorks VxWorks5.5.1) ready.
# 220 Tornado-vxWorks (VxWorks5.5.1) FTP server ready
# 220 $hostname FTP server (VxWorks 6.4) ready.
# 220 VxWorks (VxWorks 6.3) FTP server ready
# 220 Tornado-vxWorks FTP server ready
if( banner =~ "[vV]xWorks" && "FTP server" >< banner ) {
  version = eregmatch( pattern:"\(?VxWorks ?\(?([0-9.]+)", string:banner );
  if( ! isnull( version[1] ) ) {
    os_register_and_report( os:"Wind River VxWorks", version:version[1], cpe:"cpe:/o:windriver:vxworks", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else {
    os_register_and_report( os:"Wind River VxWorks", cpe:"cpe:/o:windriver:vxworks", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  }
  exit( 0 );
}

if( "Network Management Card AOS" >< banner ) {
  version = eregmatch( pattern:"Network Management Card AOS v([0-9.]+)", string:banner );
  if( ! isnull( version[1] ) ) {
    os_register_and_report( os:"APC AOS", version:version[1], cpe:"cpe:/o:apc:aos", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else {
    os_register_and_report( os:"APC AOS", cpe:"cpe:/o:apc:aos", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  }
  exit( 0 );
}

if( ( "Microsoft FTP Service" >< banner && "WINDOWS SERVER 2003" >< banner ) || "OS=Windows Server 2003;" >< banner ) {
  os_register_and_report( os:"Microsoft Windows Server 2003", cpe:"cpe:/o:microsoft:windows_server_2003", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
  exit( 0 );
}

if( "MinWin FTP server" >< banner ) {
  os_register_and_report( os:"Microsoft Windows 10 IoT", cpe:"cpe:/o:microsoft:windows_10:-:-:iot", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
  exit( 0 );
}

if( "OS=Windows 10;" >< banner ) {
  os_register_and_report( os:"Microsoft Windows 10", cpe:"cpe:/o:microsoft:windows_10", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
  exit( 0 );
}

if( "OS=Windows 8;" >< banner ) {
  os_register_and_report( os:"Microsoft Windows 8", cpe:"cpe:/o:microsoft:windows_8", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
  exit( 0 );
}

if( "OS=Windows 7;" >< banner ) {
  os_register_and_report( os:"Microsoft Windows 7", cpe:"cpe:/o:microsoft:windows_7", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
  exit( 0 );
}

if( "OS=Windows XP;" >< banner ) {
  os_register_and_report( os:"Microsoft Windows XP", cpe:"cpe:/o:microsoft:windows_xp", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
  exit( 0 );
}

if( "ProFTPD" >< banner && "(Windows" >< banner ) {
  os_register_and_report( os:"Microsoft Windows", cpe:"cpe:/o:microsoft:windows", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
  exit( 0 );
}

# FileZilla Server currently runs only on Windows
if( "FileZilla Server" >< banner ) {
  os_register_and_report( os:"Microsoft Windows", cpe:"cpe:/o:microsoft:windows", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
  exit( 0 );
}

if( "FTP Server for Windows" >< banner || "220 FTP to Windows" >< banner || "FTP/S Server for Windows" >< banner ||
    "Microsoft FTP Service" >< banner || "220 Windows server" >< banner || "220 -Microsoft FTP server" >< banner ||
    "running on Windows " >< banner || "Windows FTP Server" >< banner || "Windows NT XDS FTP server" >< banner ||
    "220 Welcom to Windows" >< banner ) {
  os_register_and_report( os:"Microsoft Windows", cpe:"cpe:/o:microsoft:windows", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
  exit( 0 );
}

if( "Windows Server 2008 SP2" >< banner ) {
  os_register_and_report( os:"Microsoft Windows Server 2008 SP2", cpe:"cpe:/o:microsoft:windows_server_2008:-:sp2", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
  exit( 0 );
}

if( "running on Windows Server 2008 R2 Enterprise" >< banner || "OS=Windows Server 2008 R2;" >< banner ) {
  os_register_and_report( os:"Microsoft Windows Server 2008 R2", cpe:"cpe:/o:microsoft:windows_server_2008:r2", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
  exit( 0 );
}

if( "running on Windows 2008" >< banner ) {
  os_register_and_report( os:"Microsoft Windows Server 2008", cpe:"cpe:/o:microsoft:windows_server_2008", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
  exit( 0 );
}

if( "Windows Server 2012 R2" >< banner ) {
  os_register_and_report( os:"Microsoft Windows Server 2012 R2", cpe:"cpe:/o:microsoft:windows_server_2012:r2", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
  exit( 0 );
}

if( "OS=Windows Server 2012;" >< banner ) {
  os_register_and_report( os:"Microsoft Windows Server 2012", cpe:"cpe:/o:microsoft:windows_server_2012", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
  exit( 0 );
}

# 220-Debian GNU/Linux 7
# 220-Debian GNU/Linux 6.0
if( "220-Debian GNU/Linux" >< banner ) {
  version = eregmatch( pattern:"Debian GNU/Linux ([0-9.]+)", string:banner );
  if( ! isnull( version[1] ) ) {
    os_register_and_report( os:"Debian GNU/Linux", version:version[1], cpe:"cpe:/o:debian:debian_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else {
    os_register_and_report( os:"Debian GNU/Linux", cpe:"cpe:/o:debian:debian_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  }
  exit( 0 );
}

if( "ProFTPD" >< banner ) {
  if( "(Debian)" >< banner || "(Raspbian)" >< banner ) {
    os_register_and_report( os:"Debian GNU/Linux", cpe:"cpe:/o:debian:debian_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "(Gentoo)" >< banner ) {
    os_register_and_report( os:"Gentoo", cpe:"cpe:/o:gentoo:linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "(powered by SuSE Linux)" >< banner ) {
    os_register_and_report( os:"SUSE Linux", cpe:"cpe:/o:novell:suse_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "220-CentOS release" >< banner ) {
    os_register_and_report( os:"CentOS", cpe:"cpe:/o:centos:centos", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "(ubuntu)" >< banner ) {
    os_register_and_report( os:"Ubuntu", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }
}

if( "This is a Linux PC" >< banner || "Linux FTP Server" >< banner ) {
  os_register_and_report( os:"Linux", cpe:"cpe:/o:linux:kernel", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

if( "220-Red Hat Enterprise Linux Server" >< banner ) {
  os_register_and_report( os:"Red Hat Enterprise Linux", cpe:"cpe:/o:redhat:enterprise_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# 220-Welcome to SUSE Linux Enterprise Server 11 SP3  (x86_64) - Kernel \r (\l).
# 220-Welcome to SUSE Linux Enterprise Server 12 SP5  (x86_64) - Kernel %r (%t).
if( banner =~ "220[- ]Welcome to SUSE Linux Enterprise Server" ) {

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

if( "220-Welcome to openSUSE" >< banner ) {
  os_register_and_report( os:"openSUSE", cpe:"cpe:/o:novell:opensuse", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

if( "FTP server (NetBSD-ftpd" >< banner ) {
  os_register_and_report( os:"NetBSD", cpe:"cpe:/o:netbsd:netbsd", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# 220 localhost FTP server (Version 6.4/OpenBSD/Linux-ftpd-0.16) ready.
# 220 example.com FTP server (Version 6.4/OpenBSD/Linux-ftpd-0.17) ready.
# nb: "Version 6.4" is not the OpenBSD Version...
if( "220-OpenBSD" >< banner || banner =~ "FTP server \(Version ([0-9.]+)/OpenBSD/Linux-ftpd-([0-9.]+)\) ready" ) {
  os_register_and_report( os:"OpenBSD", cpe:"cpe:/o:openbsd:openbsd", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# FTP server (SunOS 5.8)
if( "FTP server (SunOS" >< banner ) {
  version = eregmatch( pattern:"FTP server \(SunOS ([0-9.]+)", string:banner );
  if( ! isnull( version[1] ) ) {
    os_register_and_report( os:"SunOS", cpe:"cpe:/o:sun:sunos", version:version[1], banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else {
    os_register_and_report( os:"SunOS", cpe:"cpe:/o:sun:sunos", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  }
  exit( 0 );
}

if( "220 Solaris FTP Server" >< banner || "(Sun Solaris" >< banner ) {
  os_register_and_report( os:"Sun Solaris", cpe:"cpe:/o:sun:solaris", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# vsFTPd runs only on Unix-like systems
if( "220 (vsFTPd" >< banner ) {
  os_register_and_report( os:"Linux/Unix", cpe:"cpe:/o:linux:kernel", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# Pure-FTPd was designed for Unix-like systems. There might be windows systems out but they are probably very rare
if( "Pure-FTPd" >< banner || "PureFTPd" >< banner ) {
  os_register_and_report( os:"Linux/Unix", cpe:"cpe:/o:linux:kernel", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# WU-FTPD runs only on Unix-like systems
if( "FTP server (Version wu-" >< banner ) {
  os_register_and_report( os:"Linux/Unix", cpe:"cpe:/o:linux:kernel", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# UPS / USV on embedded OS
if( "ManageUPSnet FTP server" >< banner ) {
  os_register_and_report( os:"Linux/Unix", cpe:"cpe:/o:linux:kernel", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# localhost FTP server (Version 6.4/ARMLinux/Linux-ftpd-0.17) ready.
# nb: "Version 6.4" is not the OS Version...
if( banner =~ "FTP server \(Version ([0-9.]+)/ARMLinux/Linux-ftpd-([0-9.]+)\) ready" ) {
  os_register_and_report( os:"Linux/Unix", cpe:"cpe:/o:linux:kernel", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

if( "FTP server (Linux-ftpd) ready." >< banner ) {
  os_register_and_report( os:"Linux/Unix", cpe:"cpe:/o:linux:kernel", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# "Changing FTP Server Login Banner Message 220" in https://www-01.ibm.com/support/docview.wss?uid=nas8N1016550
if( eregmatch( pattern:"^220[- ]QTCP at .+", string:banner, icase:FALSE ) ) {
  os_register_and_report( os:"IBM iSeries / OS/400", cpe:"cpe:/o:ibm:os_400", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# e.g. 220 devicename IOS-FTP server (version 1.00) ready.
if( "IOS-FTP server" >< banner && "ready." >< banner ) {
  os_register_and_report( os:"Cisco IOS", cpe:"cpe:/o:cisco:ios", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# e.g. 220 Titan FTP Server 6.26.632 Ready.
# nb: Only runs on Windows. Note that it still reports a SYST banner as 215 UNIX Type: L8
if( "220 Titan FTP Server" >< banner ) {
  os_register_and_report( os:"Microsoft Windows", cpe:"cpe:/o:microsoft:windows", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
  exit( 0 );
}

# e.g. 220 Cornerstone MFT Server 19.00.3675 Ready.
# nb: Only runs on Windows.
if( "220 Cornerstone MFT Server" >< banner ) {
  os_register_and_report( os:"Microsoft Windows", cpe:"cpe:/o:microsoft:windows", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
  exit( 0 );
}

# e.g. 220 DrayTek FTP version 1.0
if( "220 DrayTek FTP" >< banner ) {
  os_register_and_report( os:"DrayTek Vigor Firmware", cpe:"cpe:/o:draytek:vigor_firmware", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

if( banner == "220 FTP service ready." ) {
  os_register_and_report( os:"Huawei Unknown Model Versatile Routing Platform (VRP) network device Firmware", cpe:"cpe:/o:huawei:vrp_firmware", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

if( "220 KONICA MINOLTA FTP server ready." >< banner ) {
  os_register_and_report( os:"KONICA MINOLTA Printer Firmware", cpe:"cpe:/o:konicaminolta:printer_firmware", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# nb:
# - More detailed OS Detection covered in gb_axis_devices_consolidation.nasl
# - Keep in sync with the banner used in gb_axis_devices_ftp_detect.nasl and ftpserver_detect_type_nd_version.nasl
if( banner =~ "220[- ](AXIS|Axis).+(Camera|Video Server|Station)" ) {
  os_register_and_report( os:"Axis Device Firmware / AXIS OS", cpe:"cpe:/o:axis:device_firmware", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

if( "xlweb FTP server" >< banner ) {
  os_register_and_report( os:"Honeywell Excel Web Controller Firmware", cpe:"cpe:/o:honeywell:xl_web_ii_controller", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

if( "Welcome to Linksys" >< banner ) {
  os_register_and_report( os:"Linksys Device Firmware", cpe:"cpe:/o:linksys:device_firmware", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

if( egrep( string:banner, pattern:"\((ZyWALL )?USG (FLEX )?[0-9]{2,}", icase:FALSE ) ) {
  os_register_and_report( os:"Zyxel USG Firmware", cpe:"cpe:/o:zyxel:usg_firmware", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

if( egrep( string:banner, pattern:"FTP Server \(VPN[0-9]+\)", icase:FALSE ) ) {
  os_register_and_report( os:"Zyxel VPN Firewall Firmware", cpe:"cpe:/o:zyxel:vpn_firewall_firmware", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

if( " FTP server " >< banner && "(OEM FTPD version" >< banner ) {
  os_register_and_report( os:"Epson Printer Firmware", cpe:"cpe:/o:epson:printer_firmware", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

if( " FTP server " >< banner && banner =~ "(TASKalfa|ECOSYS) " ) {
  os_register_and_report( os:"Kyocera Printer Firmware", cpe:"cpe:/o:kyocera:printer_firmware", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# 220 SHARP MX-4141N Ver 01.06.00.0f.38 FTP server.
if( banner =~ "220 SHARP .*FTP Server" ) {
  os_register_and_report( os:"SHARP Printer Firmware", cpe:"cpe:/o:sharp:printer_firmware", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

if( banner =~ "220 Dell " && banner =~ "(Laser|MFP|Printer)" ) {
  os_register_and_report( os:"Dell Printer Firmware", cpe:"cpe:/o:dell:printer_firmware", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# 220 FTP Server (ATP800) [::ffff:1.1.1.1]
if( egrep( string:banner, pattern:"220 FTP Server \(ATP[0-9]+\)", icase:FALSE ) ) {
  os_register_and_report( os:"Zyxel ATP Firewall Firmware", cpe:"cpe:/o:zyxel:atp_firewall_firmware", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# 220 example.com X2 WS_FTP Server 8.7.0(51275849) FIPS
if( egrep( string:banner, pattern:"WS_FTP Server" ) ) {
  os_register_and_report( os:"Microsoft Windows", cpe:"cpe:/o:microsoft:windows", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
  exit( 0 );
}

# e.g. 220 Welcome to Netman FTP service.
if( "Welcome to Netman FTP service." >< banner ) {
  os_register_and_report( os:"Riello NetMan 204 Firmware", cpe:"cpe:/o:riello-ups:netman_204_firmware", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# e.g. 220 Welcome to Honeywell Printer PX4ie
# More detailed OS detection in gsf/gb_honeywell_printer_ftp_detect.nasl
if( "Welcome to Honeywell Printer" >< banner ) {
  os_register_and_report( os:"Honeywell Printer Unknown Model Firmware", cpe:"cpe:/o:honeywell:printer_firmware", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# 220 Bitvise SSH Server 9.32
# 220 Bitvise SSH Server 9.32: free only for personal non-commercial use
# 220 Bitvise SSH Server 8.43
# 220 Bitvise SSH Server
#
# nb: Keep the pattern "in sync" with gsf/gb_bitvise_ssh_server_ftp_detect.nasl and ftpserver_detect_type_nd_version.nasl
if( egrep( string:banner, pattern:"220[- ]Bitvise SSH Server", icase:FALSE ) ) {
  os_register_and_report( os:"Microsoft Windows", cpe:"cpe:/o:microsoft:windows", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
  exit( 0 );
}

syst_banner = get_kb_item( "ftp/fingerprints/" + port + "/syst_banner_noauth" );

# e.g. 215 UNIX Type: L8 Version: BSD-44
# "HP-UX or AIX ftpd" according to shodan
if( "215 UNIX " >< syst_banner && "Version: BSD" >< syst_banner ) {
  os_register_and_report( os:"Linux/Unix", cpe:"cpe:/o:linux:kernel", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

csid = get_kb_item( "ftp/fingerprints/" + port + "/csid_banner_authed" );

if( banner =~ "^220 (JD )?FTP Server Ready" ) {
  if( banner =~ "^220 JD FTP Server Ready" ||
      ( csid && ( csid =~ "PORT\s+HP " || csid =~ "Directory:\s+Description:" ) ) ) {
    os_register_and_report( os:"HP Printer Firmware", cpe:"cpe:/o:hp:printer_firmware", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }
}

# Corss-platform, e.g.
# 220 Wing FTP Server 5.0.6 ready...
# 220 Wing FTP Server ready...
# 220 Wing FTP Server ready... (Wing FTP Server Free Edition)
# 220 Wing FTP Server 7.2.8 ready...
if( "220 Wing FTP Server " >< banner )
  exit( 0 );

# Cross-platform (Java) and running on Windows, Linux and Mac OS X
if( "220 CrushFTP Server Ready!" >< banner )
  exit( 0 );

os_register_unknown_banner( banner:banner, banner_type_name:BANNER_TYPE, banner_type_short:"ftp_banner", port:port );

exit( 0 );
