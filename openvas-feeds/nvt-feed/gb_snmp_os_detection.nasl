# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103429");
  script_version("2025-08-08T15:44:57+0000");
  script_tag(name:"last_modification", value:"2025-08-08 15:44:57 +0000 (Fri, 08 Aug 2025)");
  script_tag(name:"creation_date", value:"2012-02-17 10:17:12 +0100 (Fri, 17 Feb 2012)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Operating System (OS) Detection (SNMP)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_dependencies("gb_snmp_info_collect.nasl");
  script_require_udp_ports("Services/udp/snmp", 161);
  script_mandatory_keys("SNMP/sysdescr/available");

  script_tag(name:"summary", value:"SNMP sysDescr based Operating System (OS) detection.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("os_func.inc");
include("cisco_ios.inc");
include("snmp_func.inc");

SCRIPT_DESC = "Operating System (OS) Detection (SNMP)";
BANNER_TYPE = "SNMP sysDescr";

port = snmp_get_port( default:161 );

if( ! sysdesc = snmp_get_sysdescr( port:port ) )
  exit( 0 );

# Linux xy 3.16.0-4-amd64 #1 SMP Debian 3.16.36-1+deb8u2 (2016-10-19) x86_64
if( sysdesc =~ "Linux" && " Debian " >< sysdesc ) {

  set_kb_item( name:"Host/OS/SNMP/Confidence", value:100 );

  # nb: The order matters in case of backports which might have something like +deb9~bpo8
  if( "~bpo6" >< sysdesc ) {
    set_kb_item( name:"Host/OS/SNMP", value:"Debian GNU/Linux 6.0" );
    os_register_and_report( os:"Debian GNU/Linux", version:"6.0", cpe:"cpe:/o:debian:debian_linux", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  # nb: Starting with Wheezy (7.x) we have minor releases within the version so we don't use an exact version like 7.0 as we can't differ between the OS in the banner here
  } else if( "+deb7" >< sysdesc || "~bpo7" >< sysdesc ) {
    set_kb_item( name:"Host/OS/SNMP", value:"Debian GNU/Linux 7" );
    os_register_and_report( os:"Debian GNU/Linux", version:"7", cpe:"cpe:/o:debian:debian_linux", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else if( "+deb8" >< sysdesc || "~bpo8" >< sysdesc ) {
    set_kb_item( name:"Host/OS/SNMP", value:"Debian GNU/Linux 8" );
    os_register_and_report( os:"Debian GNU/Linux", version:"8", cpe:"cpe:/o:debian:debian_linux", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else if( "+deb9" >< sysdesc || "~bpo9" >< sysdesc ) {
    set_kb_item( name:"Host/OS/SNMP", value:"Debian GNU/Linux 9" );
    os_register_and_report( os:"Debian GNU/Linux", version:"9", cpe:"cpe:/o:debian:debian_linux", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else if( "+deb10" >< sysdesc || "~bpo10" >< sysdesc ) {
    set_kb_item( name:"Host/OS/SNMP", value:"Debian GNU/Linux 10" );
    os_register_and_report( os:"Debian GNU/Linux", version:"10", cpe:"cpe:/o:debian:debian_linux", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else if( "+deb11" >< sysdesc || "~bpo11" >< sysdesc ) {
    set_kb_item( name:"Host/OS/SNMP", value:"Debian GNU/Linux 11" );
    os_register_and_report( os:"Debian GNU/Linux", version:"11", cpe:"cpe:/o:debian:debian_linux", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else if( "+deb12" >< sysdesc || "~bpo12" >< sysdesc ) {
    set_kb_item( name:"Host/OS/SNMP", value:"Debian GNU/Linux 12" );
    os_register_and_report( os:"Debian GNU/Linux", version:"12", cpe:"cpe:/o:debian:debian_linux", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else {
    set_kb_item( name:"Host/OS/SNMP", value:"Debian GNU/Linux" );
    os_register_and_report( os:"Debian GNU/Linux", cpe:"cpe:/o:debian:debian_linux", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  }
  exit( 0 );
}

# SINDOH MF 3300_2300 version NR.APS.N434 kernel 2.6.18.5 All-N-1
if( sysdesc =~ " kernel [0-9]\." ) {

  set_kb_item( name:"Host/OS/SNMP", value:"Linux" );
  set_kb_item( name:"Host/OS/SNMP/Confidence", value:100 );

  version = eregmatch( pattern:"kernel ([0-9]+\.[^ ]*).*", string:sysdesc );

  if( ! isnull( version[1] ) ) {
    os_register_and_report( os:"Linux", version:version[1], cpe:"cpe:/o:linux:kernel", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else {
    os_register_and_report( os:"Linux", cpe:"cpe:/o:linux:kernel", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  }
  exit( 0 );
}

# Microsoft Corp. Windows 98.
# Hardware: x86 Family 15 Model 4 Stepping 1 AT/AT COMPATIBLE - Software: Windows 2000 Version 5.1 (Build 2600 Uniprocessor Free)
# Hardware: x86 Family 6 Model 8 Stepping 3 AT/AT COMPATIBLE - Software: Windows NT Version 4.0 (Build Number: 1381 Uniprocessor Free )
if( sysdesc =~ "Microsoft Corp. Windows 98" || sysdesc =~ "Hardware:.*Software: Windows" ) {

  set_kb_item( name:"Host/OS/SNMP", value:"Windows" );
  set_kb_item( name:"Host/OS/SNMP/Confidence", value:75 );

  if( "Windows 98" >< sysdesc ) {
    os_register_and_report( os:"Microsoft Windows 98", cpe:"cpe:/o:microsoft:windows_98", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"windows" );
    exit( 0 );
  }

  version = eregmatch( pattern:"Software: Windows.*Version ([0-9.]+)", string:sysdesc );

  if( isnull( version[1] ) || ( version[1] !~ "^[4-6]\.[0-3]" && version[1] !~ "^3\.51?" ) ) {
    os_register_and_report( os:"Microsoft Windows", cpe:"cpe:/o:microsoft:windows", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"windows" );
    exit( 0 );
  }

  winVal = version[1];

  # https://en.wikipedia.org/wiki/List_of_Microsoft_Windows_versions
  # IMPORTANT: Before registering two or more OS make sure that all OS variants have reached
  # their EOL as we currently can't control / prioritize which of the registered OS is chosen
  # for the "BestOS" and we would e.g. report a Server 2012 as EOL if Windows 8 was chosen.

  if( winVal == "3.5" ) {
    os_register_and_report( os:"Microsoft Windows NT", version:"3.5", cpe:"cpe:/o:microsoft:windows_nt", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"windows" );
    exit( 0 );
  }

  if( winVal == "3.51" ) {
    os_register_and_report( os:"Microsoft Windows NT", version:"3.51", cpe:"cpe:/o:microsoft:windows_nt", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"windows" );
    exit( 0 );
  }

  if( winVal == "4.0" ) {
    os_register_and_report( os:"Microsoft Windows NT", version:"4.0", cpe:"cpe:/o:microsoft:windows_nt", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"windows" );
    exit( 0 );
  }

  if( winVal == "5.0" ) {
    os_register_and_report( os:"Microsoft Windows 2000", cpe:"cpe:/o:microsoft:windows_2000", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"windows" );
    exit( 0 );
  }

  if( winVal == "5.1" ) {
    os_register_and_report( os:"Microsoft Windows XP", cpe:"cpe:/o:microsoft:windows_xp", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"windows" );
    exit( 0 );
  }

  if( winVal == "5.2" ) {
    os_register_and_report( os:"Microsoft Windows Server 2003 R2", cpe:"cpe:/o:microsoft:windows_server_2003:r2", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"windows" );
    os_register_and_report( os:"Microsoft Windows Server 2003", cpe:"cpe:/o:microsoft:windows_server_2003", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"windows" );
    os_register_and_report( os:"Microsoft Windows XP x64", cpe:"cpe:/o:microsoft:windows_xp:-:-:x64", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"windows" );
    exit( 0 );
  }

  if( winVal == "6.0" ) {
    # keep: os_register_and_report( os:"Microsoft Windows Server 2008", cpe:"cpe:/o:microsoft:windows_server_2008", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"windows" );
    # keep: os_register_and_report( os:"Microsoft Windows Vista", cpe:"cpe:/o:microsoft:windows_vista", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"windows" );
    os_register_and_report( os:"Microsoft Windows Server 2008 or Microsoft Windows Vista", cpe:"cpe:/o:microsoft:windows", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"windows" );
    exit( 0 );
  }

  if( winVal == "6.1" ) {
    # keep: os_register_and_report( os:"Microsoft Windows Server 2008 R2", cpe:"cpe:/o:microsoft:windows_server_2008:r2", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"windows" );
    # keep: os_register_and_report( os:"Microsoft Windows 7", cpe:"cpe:/o:microsoft:windows_7", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"windows" );
    os_register_and_report( os:"Microsoft Windows Server 2008 R2 or Microsoft Windows 7", cpe:"cpe:/o:microsoft:windows", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"windows" );
    exit( 0 );
  }

  if( winVal == "6.2" ) {
    # keep: os_register_and_report( os:"Microsoft Windows Server 2012", cpe:"cpe:/o:microsoft:windows_server_2012", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"windows" );
    # keep: os_register_and_report( os:"Microsoft Windows 8", cpe:"cpe:/o:microsoft:windows_8", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"windows" );
    os_register_and_report( os:"Microsoft Windows Server 2012 or Microsoft Windows 8", cpe:"cpe:/o:microsoft:windows", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"windows" );
    exit( 0 );
  }

  if( winVal == "6.3" ) {
    # keep: os_register_and_report( os:"Microsoft Windows Server 2012 R2", cpe:"cpe:/o:microsoft:windows_server_2012:r2", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"windows" );
    # keep: os_register_and_report( os:"Microsoft Windows 8.1", cpe:"cpe:/o:microsoft:windows_8.1", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"windows" );
    os_register_and_report( os:"Microsoft Windows Server 2012 R2 or Microsoft Windows 8.1", cpe:"cpe:/o:microsoft:windows", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"windows" );
    exit( 0 );
  }

  # we don't know the real windows version if we reached here. So just register windows.
  os_register_and_report( os:"Microsoft Windows", cpe:"cpe:/o:microsoft:windows", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"windows" );
  exit( 0 );
}

# FreeBSD localhost.localdomain 4.11-RELEASE-p26 FreeBSD 4.11-RELEASE-p26 #12: S i386
# pfSense localhost.localdomain 2.4.1-RELEASE pfSense FreeBSD 11.1-RELEASE-p2 amd64
if( sysdesc =~ "(FreeBSD|pfSense).* FreeBSD" ) {

  set_kb_item( name:"Host/OS/SNMP", value:"FreeBSD" );
  set_kb_item( name:"Host/OS/SNMP/Confidence", value:100 );

  version = eregmatch( pattern:".*FreeBSD ([0-9.]+[^ ]*).*", string:sysdesc );
  if( ! isnull( version[1] ) ) {
    os_register_and_report( os:"FreeBSD", version:version[1], cpe:"cpe:/o:freebsd:freebsd", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else {
    os_register_and_report( os:"FreeBSD", cpe:"cpe:/o:freebsd:freebsd", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  }
  exit( 0 );
}

# NetBSD localhost.localdomain 1.6.1_STABLE NetBSD 1.6.1_STABLE (SCZ_16) #0: Thu May 24 14:42:04 CEST 2007...
if( sysdesc =~ "NetBSD.* NetBSD" ) {

  set_kb_item( name:"Host/OS/SNMP", value:"NetBSD" );
  set_kb_item( name:"Host/OS/SNMP/Confidence", value:100 );

  version = eregmatch( pattern:".*NetBSD ([0-9.]+[^ ]*).*", string:sysdesc );
  if( ! isnull( version[1] ) ) {
    os_register_and_report( os:"NetBSD", version:version[1], cpe:"cpe:/o:netbsd:netbsd", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else {
    os_register_and_report( os:"NetBSD", cpe:"cpe:/o:netbsd:netbsd", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  }
  exit( 0 );
}

# Powered by OpenBSD
# OpenBSD localhost.localdomain 4.2 GENERIC#375 i386
if( sysdesc =~ "^OpenBSD" || sysdesc =~ "Powered by OpenBSD" ) {

  set_kb_item( name:"Host/OS/SNMP", value:"OpenBSD" );
  set_kb_item( name:"Host/OS/SNMP/Confidence", value:100 );

  version = eregmatch( pattern:"OpenBSD.* ([0-9.]+) GENERIC", string:sysdesc );

  if( ! isnull( version[1] ) ) {
    os_register_and_report( os:"OpenBSD", version:version[1], cpe:"cpe:/o:openbsd:openbsd", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else {
    os_register_and_report( os:"OpenBSD", cpe:"cpe:/o:openbsd:openbsd", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  }
  exit(0);
}

# HP-UX rx2600 B.11.23 U ia64 3979036319
if( sysdesc =~ "^HP-UX" ) {

  set_kb_item( name:"Host/OS/SNMP", value:"HP UX" );
  set_kb_item( name:"Host/OS/SNMP/Confidence", value:100 );

  version = eregmatch( pattern:"^HP-UX [^ ]* ([^ ]*)", string:sysdesc );

  if( ! isnull( version[1] ) ) {
    os_register_and_report( os:"HP HP-UX", version:version[1], cpe:"cpe:/o:hp:hp-ux", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else {
    os_register_and_report( os:"HP HP-UX", cpe:"cpe:/o:hp:hp-ux", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  }
  exit( 0 );
}

# SunOS NXSAM 5.10 Generic_127128-11 i86pc
# SunOS wlanapp 5.10 Generic_139555-08 sun4v
if( sysdesc =~ "^SunOS" ) {

  typ = " (sparc)";
  if( "i86pc" >< sysdesc )
    typ = " (i386)";

  set_kb_item( name:"Host/OS/SNMP", value:"Sun Solaris" + typ );
  set_kb_item( name:"Host/OS/SNMP/Confidence", value:100 );

  version = eregmatch( pattern:"^SunOS .* (5\.[0-9]+)", string:sysdesc );

  if( ! isnull( version[1] ) ) {
    os_register_and_report( os:"Sun SunOS", version:version[1], cpe:"cpe:/o:sun:sunos", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else {
    os_register_and_report( os:"Sun SunOS", cpe:"cpe:/o:sun:sunos", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  }
  exit( 0 );
}

# HP ETHERNET MULTI-ENVIRONMENT,ROM P.22.01,JETDIRECT,JD86,EEPROM P.24.07,CIDATE 12/13/2002
# HP ETHERNET MULTI-ENVIRONMENT,ROM none,JETDIRECT,JD153,EEPROM JSI23900036,CIDATE 01/15/2019
# HP ETHERNET MULTI-ENVIRONMENT,SN:PHKGG11967,FN:X684DW4,SVCID:25054,PID:HP LaserJet 400 M401dn
# HP ETHERNET MULTI-ENVIRONMENT
if( "JETDIRECT" >< sysdesc ) {

  set_kb_item( name:"Host/OS/SNMP", value:"HP JetDirect Firmware" );
  set_kb_item( name:"Host/OS/SNMP/Confidence", value:100 );

  os_register_and_report( os:"HP JetDirect Firmware", cpe:"cpe:/o:hp:jetdirect_firmware", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# nb: More detailed OS Detection covered in gb_hp_printer_snmp_detect.nasl
if( "HP ETHERNET MULTI-ENVIRONMENT" >< sysdesc ) {
  os_register_and_report( os:"HP Printer Firmware", cpe:"cpe:/o:hp:printer_firmware", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# Cisco Internetwork Operating System Software  IOS (tm) GS Software (GSR-P-M), Version 12.0(21)ST7, EARLY DEPLOYMENT RELEASE SOFTWARE (fc1)  ...
# Cisco IOS Software, C3550 Software (C3550-IPSERVICESK9-M), Version 12.2(25)SEE2, RELEASE SOFTWARE (fc1)
if( ( sysdesc =~ "^Cisco IOS" || "IOS (tm)" >< sysdesc ) && ( "Cisco IOS XR" >!< sysdesc && sysdesc !~ "(IOS-XE|Virtual XE|CSR1000V) Software" ) ) {

  set_kb_item(name:"Host/OS/SNMP", value:"Cisco IOS");
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);

  version = eregmatch(pattern:"IOS.*Version ([0-9]*\.[0-9]*\([0-9a-zA-Z]+\)[A-Z0-9.]*),", string:sysdesc);

  if( ! isnull( version[1] ) ) {
    os_register_and_report( os:"Cisco IOS", version:version[1], cpe:"cpe:/o:cisco:ios", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
    set_kb_item( name:"cisco_ios/snmp/version", value:version[1] );
    set_kb_item( name:"cisco_ios/detected", value:TRUE );
  } else {
    os_register_and_report( os:"Cisco IOS", cpe:"cpe:/o:cisco:ios", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  }
  exit( 0 );
}

# nb: More detailed OS Detection covered in gb_cisco_ios_xe_consolidation.nasl
if( ( sysdesc =~ "^Cisco IOS" || "IOS (tm)" >< sysdesc ) && "Cisco IOS XR" >!< sysdesc && sysdesc =~ "(IOS-XE|Virtual XE|CSR1000V) Software" ) {

  set_kb_item(name:"Host/OS/SNMP", value:"Cisco IOS XE");
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);

  os_register_and_report( os:"Cisco IOS XE", cpe:"cpe:/o:cisco:ios_xe", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# Ubiquiti UniFi UDM 4.1.13 Linux 4.19.152 al324
# nb: More detailed detection covered in gsf/gb_ubiquiti_unifi_os_snmp_detect.nasl
if( egrep( pattern:"^Ubiquiti UniFi", string:sysdesc, icase:FALSE ) ) {
  os_register_and_report( os:"Ubiquiti UniFi OS", cpe:"cpe:/o:ui:unifi_os", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# EdgeSwitch 24-Port 250W, 1.7.0.4922887, Linux 3.6.5-f4a26ed5, 0.0.0.0000000
# EdgeSwitch 8 150W, 1.11.0, Linux 3.6.5-03329b4a, 1.2.0.5192732
#
# nb: More detailed detection covered in gsf/gb_ubiquiti_edgeswitch_snmp_detect.nasl
if( sysdesc =~ "^EdgeSwitch " ) {
  os_register_and_report( os:"Ubiquiti EdgeSwitch Firmware", cpe:"cpe:/o:ui:edgeswitch_firmware", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# nb: More detailed OS detection covered in gsf/gb_dell_emc_smartfabric_os10_snmp_detect.nasl
if( "Dell EMC Networking OS10" >< sysdesc ) {
  set_kb_item( name:"Host/OS/SNMP", value:"Dell EMC SmartFabric OS10" );
  set_kb_item( name:"Host/OS/SNMP/Confidence", value:100 );

  os_register_and_report( os:"Dell EMC SmartFabric OS10", cpe:"cpe:/o:dell:emc_networking_os10", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# Base Operating System Runtime AIX version: 05.03.0000.0060
if( "Base Operating System Runtime AIX" >< sysdesc ) {

  set_kb_item( name:"Host/OS/SNMP", value:"AIX" );
  set_kb_item( name:"Host/OS/SNMP/Confidence", value:100 );

  version = eregmatch( pattern:"Base Operating System Runtime AIX version: ([0-9.]+)", string:sysdesc );

  if( ! isnull( version[1] ) ) {
    os_register_and_report( os:"IBM AIX", version:version[1], cpe:"cpe:/o:ibm:aix", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else {
    os_register_and_report( os:"IBM AIX", cpe:"cpe:/o:ibm:aix", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  }
  exit( 0 );
}

# Darwin localhost.localdomain 9.6.0 Darwin Kernel Version 9.6.0: Mon Nov 24 17:37:00 PST 2008; root:xnu-1228.9.59~1/RELEASE_I386 i386
if( sysdesc =~ "^Darwin [^ ]+ " || "Darwin Kernel" >< sysdesc ) {

  set_kb_item( name:"Host/OS/SNMP", value:"Apple Mac OS X" );
  set_kb_item( name:"Host/OS/SNMP/Confidence", value:100 );

  os_register_and_report( os:"Mac OS X", cpe:"cpe:/o:apple:mac_os_x", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );

  exit( 0 );
}

# Juniper Networks, Inc. ex3200-24t internet router, kernel JUNOS 10.1R1.8 #0: 2010-02-12 17:24:20 UTC ...
# Juniper Networks, Inc. m320 internet router, kernel JUNOS 10.1R3.7 #0: 2010-07-10 05:44:37 UTC ...
# Juniper Networks, Inc. srx210be internet router, kernel JUNOS 10.4R4.5 #0: 2011-05-06 06:14:23 UTC ...
# Juniper Networks, Inc. mx960 internet router, kernel JUNOS 21.2R3-S2.9, Build date: ...
# Juniper Networks, Inc. srx340 internet router, kernel JUNOS 15.1X49-D150.2, Build date: ...
# Juniper Networks, Inc. qfx10002-36q Ethernet Switch, kernel JUNOS 18.4R2-S5.4, Build date: ...
if( "Juniper Networks" >< sysdesc && "JUNOS" >< sysdesc ) {

  set_kb_item( name:"Host/OS/SNMP", value:"JUNOS" );
  set_kb_item( name:"Host/OS/SNMP/Confidence", value:100 );

  version = eregmatch( pattern:"JUNOS ([^ ]+)", string:sysdesc );

  if( ! isnull( version[1] ) ) {
    os_register_and_report( os:"Juniper Networks Junos OS", version:version[1], cpe:"cpe:/o:juniper:junos", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  }  else {
    os_register_and_report( os:"Juniper Networks Junos OS", cpe:"cpe:/o:juniper:junos", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  }
  exit( 0 );
}

# localhost.localdomain AlphaServer 1200 5/533 4MB OpenVMS V7.3-1 Compaq TCP/IP Services for OpenVMS
if( "OpenVMS" >< sysdesc ) {

  set_kb_item( name:"Host/OS/SNMP", value:"OpenVMS" );
  set_kb_item( name:"Host/OS/SNMP/Confidence", value:100 );

  version = eregmatch( pattern:"OpenVMS V([^ ]+)", string:sysdesc );

  if( ! isnull( version[1] ) ) {
    os_register_and_report( os:"HP OpenVMS", version:version[1], cpe:"cpe:/o:hp:openvms", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else {
    os_register_and_report( os:"HP OpenVMS", cpe:"cpe:/o:hp:openvms", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  }
  exit( 0 );
}

# Novell NetWare 5.70.08  October 3, 2008
if( "Novell NetWare" >< sysdesc ) {

  set_kb_item( name:"Host/OS/SNMP", value:"Novell NetWare" );
  set_kb_item( name:"Host/OS/SNMP/Confidence", value:100 );

  version = eregmatch( pattern:"Novell NetWare ([0-9.]+)", string:sysdesc );

  if( ! isnull( version[1] ) ) {
    os_register_and_report( os:"Novell NetWare", version:version[1], cpe:"cpe:/o:novell:netware", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else {
    os_register_and_report( os:"Novell NetWare", cpe:"cpe:/o:novell:netware", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  }
  exit( 0 );
}

# Silicon Graphics Octane2 running IRIX64 version 6.5
# Silicon Graphics O2 running IRIX version 6.5
if( sysdesc =~ "running IRIX(64)? version" ) {

  set_kb_item( name:"Host/OS/SNMP", value:"IRIX" );
  set_kb_item( name:"Host/OS/SNMP/Confidence", value:100 );

  version = eregmatch( pattern:"version ([0-9.]+)", string:sysdesc );

  if( ! isnull( version[1] ) ) {
    os_register_and_report( os:"SGI IRIX", version:version[1], cpe:"cpe:/o:sgi:irix", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else {
    os_register_and_report( os:"SGI IRIX", cpe:"cpe:/o:sgi:irix", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  }
  exit( 0 );
}

# SCO OpenServer Release 6
if( "SCO OpenServer" >< sysdesc ) {

  set_kb_item( name:"Host/OS/SNMP", value:"SCO OpenServer" );
  set_kb_item( name:"Host/OS/SNMP/Confidence", value:100 );

  version = eregmatch( pattern:"SCO OpenServer Release ([0-9]+)", string:sysdesc );

  if( ! isnull( version[1] ) ) {
    os_register_and_report( os:"SCO OpenServer", version:version[1], cpe:"cpe:/o:sco:openserver", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else {
    os_register_and_report( os:"SCO OpenServer", cpe:"cpe:/o:sco:openserver", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  }
  exit( 0 );
}

# SCO UnixWare 7.1.4
if( "SCO UnixWare" >< sysdesc ) {

  set_kb_item( name:"Host/OS/SNMP", value:"SCO UnixWare" );
  set_kb_item( name:"Host/OS/SNMP/Confidence", value:100 );

  version = eregmatch( pattern:"SCO UnixWare ([0-9.]+)", string:sysdesc );

  if( ! isnull( version[1] ) ) {
    os_register_and_report( os:"SCO UnixWare", version:version[1], cpe:"cpe:/o:sco:unixware", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else {
    os_register_and_report( os:"SCO UnixWare", cpe:"cpe:/o:sco:unixware", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  }
  exit( 0 );
}

# Novell UnixWare v2.1
if( "Novell UnixWare" >< sysdesc ) {

  set_kb_item( name:"Host/OS/SNMP", value:"Novell UnixWare" );
  set_kb_item( name:"Host/OS/SNMP/Confidence", value:100 );

  version = eregmatch( pattern:"Novell UnixWare v([0-9.]+)", string:sysdesc );

  if( ! isnull( version[1] ) ) {
    os_register_and_report( os:"Novell UnixWare", version:version[1], cpe:"cpe:/o:novell:unixware", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else {
    os_register_and_report( os:"Novell UnixWare", cpe:"cpe:/o:novell:unixware", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  }
  exit( 0 );
}

if( "ProSafe" >< sysdesc || "ProSAFE" >< sysdesc ) {
  exit( 0 ); # 1.3.6.1.4.1.25623.1.0.108163 (gb_netgear_prosafe_snmp_detect.nasl)
}

if( "Cisco IOS XR" >< sysdesc ) {
  exit( 0 ); # 1.3.6.1.4.1.25623.1.0.105079 (gb_cisco_ios_xr_snmp_detect.nasl)
}

if( "ArubaOS" >< sysdesc ) {
  exit( 0 ); # 1.3.6.1.4.1.25623.1.0.105244 (gb_aruba_arubaos_snmp_detect.nasl)
}

if( "Cisco NX-OS" >< sysdesc ) {
  exit( 0 ); # 1.3.6.1.4.1.25623.1.0.103799 (gb_cisco_nx_os_detect.nasl)
}

if( "Cisco Adaptive Security Appliance" >< sysdesc ) {
  exit( 0 ); # 1.3.6.1.4.1.25623.1.0.106513 (gb_cisco_asa_version_snmp.nasl)
}

if( "Arista Networks EOS" >< sysdesc ) {
  exit( 0 ); # 1.3.6.1.4.1.25623.1.0.106494 (gb_arista_eos_snmp_detect.nasl)
}

if( sysdesc =~ "^HyperIP" ) {
  exit( 0 ); # 1.3.6.1.4.1.25623.1.0.108349 (gb_hyperip_snmp_detect.nasl)
}

if( "Siemens, SIMATIC HMI" >< sysdesc ) { # 1.3.6.1.4.1.25623.1.0.141682 (gb_simatic_hmi_snmp_detect.nasl)
  exit( 0 );
}

if( sysdesc =~ "^SMS [^ ]+ v?SMS" ) {
  exit( 0 ); # 1.3.6.1.4.1.25623.1.0.108569 (gb_tippingpoint_sms_snmp_detect.nasl)
}

if( "Crestron Electronics AM-" >< sysdesc ) {
  exit( 0 ); # 1.3.6.1.4.1.25623.1.0.141392 (gb_crestron_airmedia_snmp_detect.nasl)
}

if( sysdesc =~ "^ ?LANCOM" ) {
  exit( 0 ); # 1.3.6.1.4.1.25623.1.0.143421 (gb_lancom_devices_snmp_detect.nasl)
}

if( "DGS-1500" >< sysdesc ) {
  exit( 0 ); # 1.3.6.1.4.1.25623.1.0.107252 (gb_dgs_1500_detect.nasl)
}

# nb: More detailed OS Detection covered in gsf/gb_zyxel_usg_snmp_detect.nasl
if( sysdesc =~ "^(ZyWall )?USG (FLEX )?[0-9]" ) {
  os_register_and_report( os:"Zyxel USG Firmware", cpe:"cpe:/o:zyxel:usg_firmware", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# nb: More detailed OS Detection covered in gsf/gb_zyxel_vpn_firewall_snmp_detect.nasl
if( egrep( pattern:"^VPN[0-9]+$", string:sysdesc, icase:FALSE ) ) {
  os_register_and_report( os:"Zyxel VPN Firewall Firmware", cpe:"cpe:/o:zyxel:vpn_firewall_firmware", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# nb: More detailed OS Detection covered in gb_netapp_data_ontap_consolidation.nasl
if( sysdesc =~ "^NetApp Release " ) {
  os_register_and_report( os:"NetApp Data ONTAP", cpe:"cpe:/o:netapp:data_ontap", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# nb: More detailed OS Detection covered in gsf/gb_ruckus_zonedirector_snmp_detect.nasl
if( sysdesc =~ "^Ruckus Wireless ZD[0-9]+" ) {
  os_register_and_report( os:"Ruckus ZoneDirector Firmware", cpe:"cpe:/o:ruckuswireless:zonedirector_firmware", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# nb: More detailed OS Detection covered in gsf/gb_aruba_switches_snmp_detect.nasl
if( sysdesc =~ "^(Aruba|HP|ProCurve) .*Switch" ) {
  os_register_and_report( os:"Aruba/HP/HPE Switch Firmware", cpe:"cpe:/o:arubanetworks:switch_firmware", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# nb: More detailed OS Detection covered in gb_draytek_vigor_consolidation.nasl
if( sysdesc =~ "^DrayTek.+Router Model" || sysdesc =~ "^DrayTek Corporation" || sysdesc =~ "^Linux Draytek " ) {
  os_register_and_report( os:"DrayTek Vigor Firmware", cpe:"cpe:/o:draytek:vigor_firmware", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# nb: More detailed OS Detection covered in gb_cambium_cnpilot_snmp_detect.nasl
if( sysdesc =~ "^(Cambium )?cnPilot" ) {
  os_register_and_report( os:"Cambium Networks cnPilot Firmware", cpe:"cpe:/o:cambiumnetworks:cnpilot_firmware", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

if( "Option CloudGate" >< sysdesc ) {
  os_register_and_report( os:"Option CloudGate Firmware", cpe:"cpe:/o:option:cloudgate_firmware", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# nb: More detailed OS Detection covered in gsf/gb_cisco_nam_snmp_detect.nasl
if( sysdesc =~ "(Cisco )?Network Analysis Module" &&
    egrep( pattern:"Cisco Systems", string:sysdesc, icase:TRUE ) ) {
  os_register_and_report( os:"Cisco NAM", cpe:"cpe:/o:cisco:prime_network_analysis_module_firmware", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# nb: More detailed OS Detection covered in gb_zhone_znid_gpon_snmp_detect.nasl
if( "ZNID-GPON" >< sysdesc || "Zhone Indoor Network Interface" >< sysdesc ) {
  os_register_and_report( os:"ZHONE ZNID GPON Firmware", cpe:"cpe:/o:dasanzhone:znid_firmware", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# nb: More detailed OS Detection covered in gb_cisco_small_business_switch_snmp_detect.nasl
if( sysdesc =~ "S(G|F)[0-9]{3}.*(Stackable Managed|Managed|Smart) Switch$" ) {
  os_register_and_report( os:"Cisco Small Business Switch Firmware", cpe:"cpe:/o:cisco:small_business_switch_firmware", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# nb: More detailed OS Detection covered in gb_cisco_small_business_devices_snmp_detect.nasl
if( sysdesc =~ "Cisco Small Business" ) {
  os_register_and_report( os:"Cisco Small Business Firmware", cpe:"cpe:/o:cisco:small_business_firmware", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# nb: More detailed OS Detection covered in gb_huawei_VP9660_mcu_detect.nasl
if( "HUAWEI VP9660" >< sysdesc ) {
  os_register_and_report( os:"Huawei VP9660 MCU Firmware", cpe:"cpe:/o:huawei:vp_9660_firmware", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# nb: More detailed OS Detection covered in gb_hpe_officeconnect_switch_snmp_detect.nasl
if( sysdesc =~ "HP[E]?( OfficeConnect)?( Switch)? [0-9]{4}" ) {
  os_register_and_report( os:"HPE OfficeConnect Switch Firmware", cpe:"cpe:/o:hpe:officeconnect_firmware", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# nb: More detailed OS Detection covered in gsf/gb_hpe_instant_on_switch_snmp_detect.nasl
if( sysdesc =~ "^(Aruba|HPE Networking) Instant On.*Switch" ) {
  os_register_and_report( os:"HPE Instant On Switch Firmware", cpe:"cpe:/o:hpe:aruba_instant_on_switch_firmware", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

if( "WatchGuard Fireware" >< sysdesc ) {

  set_kb_item( name:"Host/OS/SNMP", value:"WatchGuard Fireware" );
  set_kb_item( name:"Host/OS/SNMP/Confidence", value:100 );

  version = eregmatch( pattern:"WatchGuard Fireware v([0-9.]+)", string:sysdesc );

  if( ! isnull( version[1] ) ) {
    register_product( cpe:"cpe:/o:watchguard:fireware:" + version[1] );
    os_register_and_report( os:"WatchGuard Fireware", version:version[1], cpe:"cpe:/o:watchguard:fireware", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else {
    os_register_and_report( os:"WatchGuard Fireware", cpe:"cpe:/o:watchguard:fireware", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  }
  exit( 0 );
}

if( sysdesc =~ 'HP Comware (Platform )?Software' ) {
  os_register_and_report( os:"HP Comware OS", cpe:"cpe:/o:hp:comware_os", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# Assume Linux/Unix for this device
if( "Triax TDX" >< sysdesc ) {
  os_register_and_report( os:"Linux/Unix", cpe:"cpe:/o:linux:kernel", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# e.g. IBM OS/400 V7R3M0
# IBM OS/400 V7R1M0
if( "IBM OS/400" >< sysdesc ) {
  version = eregmatch( pattern:"^IBM OS/400 ([^ ]+)", string:sysdesc );
  if( ! isnull( version[1] ) ) {
    os_register_and_report( os:"IBM OS/400", version:tolower( version[1] ), cpe:"cpe:/o:ibm:os_400", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else {
    os_register_and_report( os:"IBM OS/400", cpe:"cpe:/o:ibm:os_400", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  }
  exit( 0 );
}

# nb: More detailed OS Detection covered in gb_sato_printer_snmp_detect.nasl
if( sysdesc =~ "^SATO " ) {
  os_register_and_report( os:"SATO Printer Firmware", cpe:"cpe:/o:sato:printer_firmware", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# nb: More detailed OS Detection covered in gsf/gb_konicaminolta_printer_snmp_detect.nasl
if( sysdesc =~ "^KONICA MINOLTA " ) {
  os_register_and_report( os:"KONICA MINOLTA Printer Firmware", cpe:"cpe:/o:konicaminolta:printer_firmware", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# nb: More detailed OS Detection covered in gsf/gb_vxworks_snmp_detect.nasl
if( egrep( pattern:"VxWorks", string:sysdesc, icase:TRUE ) ) {
  os_register_and_report( os:"Wind River VxWorks", cpe:"cpe:/o:windriver:vxworks", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# nb: More detailed OS Detection covered in gb_westermo_weos_snmp_detect.nasl
if( egrep( pattern:"^Westermo.*, primary:.*, backup:.*, bootloader:", string:sysdesc, icase:TRUE ) ) {
  os_register_and_report( os:"Westermo WeOS", cpe:"cpe:/o:westermo:weos", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# nb:
# - More detailed OS Detection covered in gb_epson_printer_snmp_detect.nasl
# - Case insensitive match (via "=~") is expected / done on purpose
if( sysdesc =~ "^EPSON " ) {
  os_register_and_report( os:"Epson Printer Firmware", cpe:"cpe:/o:epson:printer_firmware", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# nb: More detailed OS Detection covered in gb_toshiba_printer_snmp_detect.nasl
if( sysdesc =~ "^TOSHIBA (e-STUDIO|TEC)" ) {
  os_register_and_report( os:"TOSHIBA Printer Firmware", cpe:"cpe:/o:toshibatec:printer_firmware", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# e.g.:
# Canon iR1024 /P
# Canon MF240 Series /P
# - More detailed OS Detection covered in gb_canon_printer_snmp_detect.nasl
# - Case insensitive match (via "=~") is expected / done on purpose
if( sysdesc =~ "^Canon " ) {
  os_register_and_report( os:"Canon Printer Firmware", cpe:"cpe:/o:canon:printer_firmware", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# e.g.:
# KYOCERA Document Solutions Printing System
# - More detailed OS Detection covered in gb_kyocera_printer_snmp_detect.nasl
# - Case insensitive match (via "=~") is expected / done on purpose
if( sysdesc =~ "^KYOCERA Document Solutions Printing System" ) {
  os_register_and_report( os:"Kyocera Printer Firmware", cpe:"cpe:/o:kyocera:printer_firmware", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# e.g.:
# SHARP MX-M314N
# SHARP BP-70C31
# - More detailed OS Detection covered in gb_sharp_printer_snmp_detect.nasl
# - Case insensitive match (via "=~") is expected / done on purpose
if( sysdesc =~ "^SHARP " ) {
  os_register_and_report( os:"SHARP Printer Firmware", cpe:"cpe:/o:sharp:printer_firmware", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# e.g.:
# Xerox(R) B225 MFP
# Xerox AltaLink C8045
# - More detailed OS Detection covered in gb_xerox_printer_consolidation.nasl
# - Case insensitive match (via "=~") is expected / done on purpose as different writings of XEROX
#   vs. Xerox has been seen
if( sysdesc =~ "^Xerox( \(R\))? " ) {
  os_register_and_report( os:"Xerox Printer Firmware", cpe:"cpe:/o:xerox:printer_firmware", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# e.g.:
# FUJI XEROX DocuColor 1450 GA
# FUJIFILM ApeosPort C2410SD
# FX DocuPrint P115 w
# - More detailed OS Detection covered in gb_fujifilm_printer_consolidation.nasl
# - Case insensitive match (via "=~") is expected / done on purpose as different writings of XEROX
#   vs. Xerox has been seen
if( sysdesc =~ "^(FUJI XEROX|FUJIFILM|FX DocuPrint) " ) {
  os_register_and_report( os:"Fujifilm Printer Firmware", cpe:"cpe:/o:fujifilm:printer_firmware", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# More detailed OS Detection covered in gb_dell_printer_consolidation.nasl
if( sysdesc =~ "^Dell .*(Laser|Printer|MFP)" ) {
  os_register_and_report( os:"Dell Printer Firmware", cpe:"cpe:/o:dell:printer_firmware", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# More detailed OS Detection covered in gsf/gb_watchguard_firebox_snmp_detect.nasl
if( sysdesc =~ "^(XTM([0-9]+(-[AFPRW])?)|T[0-9]{2}(-W)?|M[0-9]+|Firebox(V|Cloud)?(-[A-Z]+)?)$" ) {
  os_register_and_report( os:"WatchGuard Fireware Firmware", cpe:"cpe:/o:watchguard:fireware", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# More detailed OS Detection covered in e.g. gb_dell_sonicwall_tz_snmp_detect.nasl
if( "SonicOS" >< sysdesc ) {
  os_register_and_report( os:"SonicWall SonicOS", cpe:"cpe:/o:sonicwall:sonicos", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# e.g.:
# SonicWall SMA 400 (9.0.0.11-31sv)
# More detailed OS detection in VTs like e.g. gb_dell_sonicwall_sma_sra_consolidation.nasl
if( egrep( pattern:"SonicW[Aa][Ll]{2} SMA", string:sysdesc, icase:FALSE ) ) {
  os_register_and_report( os:"SonicWall SMA Firmware", cpe:"cpe:/o:sonicwall:sma_firmware", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# e.g.:
# Dell SonicWALL SRA Virtual Appliance ( 8.1.0.10-25sv)
# More detailed OS detection in VTs like e.g. gb_dell_sonicwall_sma_sra_consolidation.nasl
if( egrep( pattern:"SonicW[Aa][Ll]{2} SRA", string:sysdesc, icase:FALSE ) ) {
  os_register_and_report( os:"SonicWall SRA Firmware", cpe:"cpe:/o:sonicwall:sra_firmware", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# More detailed OS Detection covered in e.g. gsf/gb_turck_snmp_detect.nasl
if( sysdesc =~ "^Turck," ) {
  os_register_and_report( os:"Turck Device Firmware", cpe:"cpe:/o:turck:device_firmware", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# More detailed OS Detection covered in e.g. gsf/gb_paloalto_panos_snmp_detect.nasl
if( sysdesc =~ "^Palo Alto Networks" ) {
  os_register_and_report( os:"Palo Alto PAN-OS", cpe:"cpe:/o:paloaltonetworks:pan-os", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# More detailed OS Detection covered in e.g. gb_mikrotik_router_routeros_snmp_detect.nasl
if( sysdesc =~ "^RouterOS " ) {
  os_register_and_report( os:"Mikrotik Router OS", cpe:"cpe:/o:mikrotik:routeros", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# e.g.:
# NS-BSD SN160W<redacted> arm
if( sysdesc =~ "^NS\-BSD SN[0-9]" ) {
  os_register_and_report( os:"FreeBSD", cpe:"cpe:/o:freebsd:freebsd", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# Linux SOA1000 2.6.26.8 #62 SMP Mon Sep 21 18:13:37 CST 2009 i686 unknown
# BIG-IP Virtual Edition : Linux 3.10.0-862.14.4.el7.ve.x86_64 : BIG-IP software release 15.1.5.1, build 0.0.14
if( sysdesc =~ "Linux" && "Cisco IOS" >!< sysdesc ) {

  set_kb_item( name:"Host/OS/SNMP", value:"Linux" );
  set_kb_item( name:"Host/OS/SNMP/Confidence", value:100 );

  if( "BIG-IP " >< sysdesc )
    version = eregmatch( pattern:"BIG-IP [^:]+ : Linux ([0-9]+\.[^ ]*).*", string:sysdesc );
  else
    version = eregmatch( pattern:"Linux [^ ]* ([0-9]+\.[^ ]*).*", string:sysdesc );

  if( version[1] ) {

    # 2.0 SP2:
    # Linux hostname 3.10.0-327.59.59.37.h22.x86_64 #1 SMP Tue Sep 26 07:38:08 UTC 2017 x86_64
    # Unknown 2.0 release (SP5?)
    # Linux hostname 3.10.0-327.62.59.83.h163.x86_64 #1 SMP Wed Jan 16 06:10:00 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux
    if( version[1] =~ "\.h[0-9]+" ) {
      os_register_and_report( os:"Huawei EulerOS", cpe:"cpe:/o:huawei:euleros", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
      exit( 0 );
    }

    # Oracle Linux 7.4
    # Linux hostname 4.1.12-112.14.15.el7uek.x86_64 #2 SMP Thu Feb 8 09:58:19 PST 2018 x86_64 x86_64 x86_64 GNU/Linux
    if( ".el" >< version[1] && "uek." >< version[1] ) {
      version = eregmatch( pattern:"\.el([0-9]+)", string:version[1] );
      if( ! isnull( version[1] ) ) {
        os_register_and_report( os:"Oracle Linux", version:version[1], cpe:"cpe:/o:oracle:linux", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else {
        os_register_and_report( os:"Oracle Linux", cpe:"cpe:/o:oracle:linux", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
      }
      exit( 0 );
    }

    # e.g. CentOS 7.4 but also on RHEL
    # Linux hostname 3.10.0-693.el7.x86_64 #1 SMP Tue Aug 22 21:09:27 UTC 2017 x86_64 x86_64 x86_64 GNU/Linux
    # nb: Keep below the Oracle Linux check above
    if( ".el" >< version[1] ) {
      version = eregmatch( pattern:"\.el([0-9]+)", string:version[1] );
      if( ! isnull( version[1] ) ) {
        os_register_and_report( os:"Red Hat Enterprise Linux / CentOS", version:version[1], cpe:"cpe:/o:redhat:enterprise_linux", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else {
        os_register_and_report( os:"Red Hat Enterprise Linux / CentOS", cpe:"cpe:/o:redhat:enterprise_linux", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
      }
      exit( 0 );
    }

    # Fedora Core 24
    # Linux hostname 4.9.6-100.fc24.x86_64 #1 SMP Thu Jan 26 10:21:30 UTC 2017 x86_64 x86_64 x86_64 GNU/Linux
    if( ".fc" >< version[1] ) {
      version = eregmatch( pattern:"\.fc([0-9]+)", string:version[1] );
      if( ! isnull( version[1] ) ) {
        os_register_and_report( os:"Fedora Core", version:version[1], cpe:"cpe:/o:fedoraproject:fedora_core", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else {
        os_register_and_report( os:"Fedora Core", cpe:"cpe:/o:fedoraproject:fedora_core", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
      }
      exit( 0 );
    }
  }

  if( ! isnull( version[1] ) ) {
    os_register_and_report( os:"Linux", version:version[1], cpe:"cpe:/o:linux:kernel", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else {
    os_register_and_report( os:"Linux", cpe:"cpe:/o:linux:kernel", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  }
  exit( 0 );
}

# Siemens, SIMOCODE pro V PN, 3UF7 011-1AB00-0, FW: Version V01.02.00
if( sysdesc =~ "^Siemens, SIMOCODE" ) {
  os_register_and_report( os:"Siemens SIMOCODE Firmware", cpe:"cpe:/o:siemens:simocode_firmware", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

if( egrep( string:sysdesc, pattern:"^Meraki [^ ]+", icase:FALSE ) ) {
  os_register_and_report( os:"Cisco Meraki Firmware", cpe:"cpe:/o:cisco:meraki_firmware", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# ATP500
# nb: More detailed OS detection covered in gsf/gb_zyxel_atp_snmp_detect.nasl
if( egrep( pattern:"^ATP[0-9]+$", string:sysdesc, icase:FALSE ) ) {
  os_register_and_report( os:"Zyxel ATP Firewall Firmware", cpe:"cpe:/o:zyxel:atp_firewall_firmware", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# UAG2100
# nb: More detailed OS detection covered in gsf/gb_zyxel_uag_snmp_detect.nasl
if( egrep( pattern:"^UAG[0-9]+$", string:sysdesc, icase:FALSE ) ) {
  os_register_and_report( os:"Zyxel UAG Firmware", cpe:"cpe:/o:zyxel:uag_firmware", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# XGS4600-32F
# nb: More detailed OS detection covered in gsf/gb_zyxel_switch_snmp_detect.nasl
if( egrep( pattern:"^(XG|X|G|E)S[0-9A-Z-]+$", string:sysdesc, icase:FALSE ) ) {
  os_register_and_report( os:"Zyxel Switch Firmware", cpe:"cpe:/o:zyxel:switch_firmware", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# 3Com Baseline Switch 2920-SFP Plus Software Version 5.20 Release 1101P09
# nb: More detailed OS detection covered in gsf/gb_hp_3com_switch_snmp_detect.nasl
if( egrep( pattern:"^3Com .*Switch", string:sysdesc ) ) {
  os_register_and_report( os:"HP / 3Com Switch Firmware", cpe:"cpe:/o:3com:switch_firmware", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# nb: More detailed OS detection covered in gb_greenbone_os_snmp_detect.nasl
if( egrep( pattern:"^Greenbone (Security Manager|Enterprise Appliance)", string:sysdesc, icase:FALSE ) ) {
  os_register_and_report( os:"Greenbone OS (GOS)", cpe:"cpe:/o:greenbone:greenbone_os", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# nb: More detailed detection covered in gsf/gb_barracuda_cloudgen_firewall_snmp_detect.nasl
if( "Barracuda CloudGen Firewall" >< sysdesc ) {
  os_register_and_report( os:"Barracuda CloudGen Firewall Firmware", cpe:"cpe:/o:barracuda:cloudgen_firewall_firmware", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# nb: More detailed detection covered in gb_cisco_wlc_snmp_detect.nasl
if( egrep( pattern:"^Cisco Controller$", string:sysdesc, icase:FALSE ) ) {
  os_register_and_report( os:"Cisco Wireless LAN Controller Firmware", cpe:"cpe:/o:cisco:wireless_lan_controller", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# nb: More detailed detection covered in gb_technicolor_tc7200_snmp_detect.nasl
if( "VENDOR: Technicolor" >< sysdesc && "TC7200" >< sysdesc ) {
  os_register_and_report( os:"Technicolor TC7200 Firmware", cpe:"cpe:/o:technicolor:tc7200_firmware", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# nb: More detailed detection covered in gsf/gb_alcatel_omniswitch_snmp_detect.nasl
if( sysdesc =~ "^Alcatel-Lucent Enterprise OS[0-9]+" ) {
  os_register_and_report( os:"Alcatel-Lucent OmniSwitch Firmware", cpe:"cpe:/o:alcatel-lucent:omniswitch_firmware", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# nb: More detailed detection covered in gsf/gb_arrayos_snmp_detect.nasl
if( sysdesc =~ "Software\s*:\s*ArrayOS" ) {
  os_register_and_report( os:"Array ArrayOS", cpe:"cpe:/o:arraynetworks:arrayos", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# nb: More detailed detection covered in gsf/gb_riello_ups_netman_204_snmp_detect.nasl
if( sysdesc =~ "^NetMan 204" ) {
  os_register_and_report( os:"Riello NetMan 204 Firmware", cpe:"cpe:/o:riello-ups:netman_204_firmware", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# nb: More detailed detection covered in gsf/gb_moxa_miineport_snmp_detect.nasl
if( sysdesc =~ "^MiiNePort" ) {
  os_register_and_report( os:"Moxa MiiNePort Firmware", cpe:"cpe:/o:moxa:miineport_firmware", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# nb: More detailed detection covered in gsf/gb_moxa_eds_snmp_detect.nasl
if( sysdesc =~ "^Moxa EDS-G?[0-9]" ) {
  os_register_and_report( os:"Moxa EDS Firmware", cpe:"cpe:/o:moxa:eds_firmware", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# nb: More detailed detection covered in gb_citrix_netscaler_snmp_detect.nasl
if( sysdesc =~ "^NetScaler NS" ) {
  os_register_and_report( os:"Citrix NetScaler OS", cpe:"cpe:/o:citrix:netscaler", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

if( # e.g.:
    # 24-Port GbE L2+ Managed Fiber Switch
    # nb: Seen on at least these two vendors / devices
    egrep( string:sysdesc, pattern:"^[0-9]+-Port GbE L2\+ Managed Fiber Switch$", icase:FALSE ) ||
    # e.g.
    # Industrial 8-P GbE RJ45 + 4-P GbE SFP L2 Plus Managed Carrier Ethernet PoE Switch
    # Industrial 8-P GbE RJ45 + 2-P GbE SFP L2 Plus Managed Carrier Ethernet PoE++ Switch
    # Industrial 6-P GbE RJ45 + 2-P GbE SFP L2 Plus Managed Carrier Ethernet PoE Switch
    # nb: Only seen on Barox so far but both vendors might share the same base so Optilink is (at
    # least for now / until otherwise proofed) registered as well.
    egrep( string:sysdesc, pattern:"^Industrial [0-9]-P GbE RJ45 \+ [0-9]-P GbE SFP L2 Plus Managed Carrier Ethernet PoE(\+\+)? Switch$", icase:FALSE )
  ) {
  os_register_and_report( os:"Barox Switch Firmware", cpe:"cpe:/o:barox:switch_firmware", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  os_register_and_report( os:"Optilink Switch Firmware", cpe:"cpe:/o:optilink:switch_firmware", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# From https://www.meinbergglobal.com/english/products/ntp-time-server.htm#prgchar:
# Operating System of the SBC: Linux with nano kernel (incl. PPSkit)
# nb: More detailed detection covered in gb_meinberg_lantime_consolidation.nasl
if( "Meinberg LANTIME" >< sysdesc ) {
  os_register_and_report( os:"Meinberg LANTIME Firmware", cpe:"cpe:/o:meinbergglobal:lantime_firmware", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# WAGO 750-8212 PFC200 G2 2ETH RS
# WAGO 750-881 PFC ETHERNET
# WAGO IO-IPC
# nb: More detailed detection covered in gb_wago_plc_snmp_detect.nasl
if( egrep( pattern:"^WAGO ", string:sysdesc, icase:FALSE ) ) {
  os_register_and_report( os:"WAGO PLC Controller Firmware", cpe:"cpe:/o:wago:plc_firmware", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# Rockwell Automation 1756-L83E/B
# nb: More detailed detection covered in gsf/gb_rockwell_controllogix_snmp_detect.nasl
if( sysdesc =~ "Rockwell Automation 175[0-9]\-[A-Z0-9]{4}" ) {
  os_register_and_report( os:"Rockwell Automation ControlLogix Firmware", cpe:"cpe:/o:rockwellautomation:controllogix_firmware", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# nb:
# - Keep in sync with the pattern used in gsf/gb_honeywell_printer_snmp_detect.nasl and
#   dont_print_on_printers.nasl
# - The model regex below should be checked from time to time to include possible additional
#   models
if( sysdesc =~ "^Honeywell P[CMXD][0-9]+" ) {
  os_register_and_report( os:"Honeywell Printer Unknown Model Firmware", cpe:"cpe:/o:honeywell:printer_firmware", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# Extreme Networks EXOS Switches
# nb: More detailed detection covered in gb_extremeos_snmp_detect.nasl
if( "ExtremeXOS" >< sysdesc ) {
  os_register_and_report( os:"Extreme ExtremeXOS (EXOS)", cpe:"cpe:/o:extremenetworks:exos", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# Pulse Secure, LLC,Pulse Connect Secure,SA-2500,8.1R11 (build 52981)
# Pulse Secure,LLC,Pulse Connect Secure,MAG-SM160,8.1R7 (build 41041)
# Pulse Secure, LLC,Ivanti Connect Secure,PSA-3000,9.1R18.2 (build 24467)
# Pulse Secure, LLC,Ivanti Connect Secure,ISA-V,22.3R1 (build 1647)
#
# nb:
# - Please keep the pattern used here in sync with the one used in gb_pulse_connect_secure_snmp_detect.nasl
# - The appliance/server runs only on Linux based systems
#
if( sysdesc =~ "(Ivanti|Pulse) Connect Secure" && "Pulse Secure" >< sysdesc ) {
  os_register_and_report( os:"Linux", cpe:"cpe:/o:linux:kernel", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# SCHNEIDER M241-51 Fast Ethernet TCP/IP
# SCHNEIDER M258 Fast Ethernet TCP/IP
# nb: More detailed detection covered in gsf/gb_schneider_modicon_controller_snmp_detect.nasl
if( egrep( pattern:"^SCHNEIDER M[0-9]{3}.*Fast Ethernet TCP/IP", string:sysdesc, icase:FALSE ) ) {
  os_register_and_report( os:"Schneider Electric Modicon Controller Firmware", cpe:"cpe:/o:schneider-electric:modicon_controller_firmware", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# Kerio Control 9.2.7 build 2921; Kerio OS
# nb: More detailed detection covered in gsf/gb_kerio_control_snmp_detect.nasl
if( egrep( pattern:"^Kerio Control", string:sysdesc, icase:FALSE ) ) {
  os_register_and_report( os:"Kerio Control Operating System", cpe:"cpe:/o:kerio:control_operating_system", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# Linux Tower 6.6.68-Unraid #1 SMP PREEMPT_DYNAMIC Tue Dec 31 13:42:37 PST 2024 x86_64
# nb: More detailed detection covered in gb_unraid_snmp_detect.nasl
if( egrep( pattern:"^Linux [^0-9]*[0-9.]-+Unraid", string:sysdesc, icase:FALSE ) ) {
  os_register_and_report( os:"Unraid OS", cpe:"cpe:/o:unraid:unraid", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# Product: MG 600;SW Version: 6.20A.045.001
# Product: Mediant 1000;SW Version: 4.60A.016.003
# nb: More detailed detection covered in gsf/gb_audiocodes_sbc_snmp_detect.nasl
if( egrep( pattern:"^Product\s*:\s*(MG|Mediant) [^;]+;SW Version", string:sysdesc, icase:FALSE ) ) {
  os_register_and_report( os:"AudioCodes Mediant Firmware", cpe:"cpe:/o:audiocodes:mediant_firmware", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# SEPPmail Secure E-mail Gateway
# nb: More detailed detection covered in gsf/gb_seppmail_secure_email_gateway_snmp_detect.nasl
if( egrep( pattern:"^SEPPmail Secure E-mail Gateway", string:sysdesc, icase:FALSE ) ) {
  os_register_and_report( os:"Linux", cpe:"cpe:/o:linux:kernel", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# NSX Unified Appliance 4.1.2.1.0 build 22667794 VMware x86_64
if( sysdesc =~ "^NSX Unified Appliance" ) {
  os_register_and_report( os:"Linux", cpe:"cpe:/o:linux:kernel", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# Just this (for at least 1.x and 3.x):
#
# Cisco Identity Services Engine
#
# nb: More detailed detection covered in gsf/gb_cisco_ise_snmp_detect.nasl
if( sysdesc =~ "^Cisco Identity Services Engine" ) {
  os_register_and_report( os:"Cisco Application Deployment Engine OS (ADE-OS)", cpe:"cpe:/o:cisco:application_deployment_engine", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# e.g.:
#
# MINI-LINK Compact Node
# MINI-LINK 6352 80/21L
# MINI-LINK 6352 80/21H
#
# nb:
# - More detailed detection covered in gsf/gb_ericsson_mini-link_snmp_detect.nasl
# - Keep the pattern below in sync with that one
if( egrep( pattern:"^MINI-LINK ", string:sysdesc, icase:FALSE ) ) {
  os_register_and_report( os:"Ericsson MINI-LINK Device Firmware", cpe:"cpe:/o:ericsson:mini_link_device_firmware", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

os_register_unknown_banner( banner:sysdesc, banner_type_name:BANNER_TYPE, banner_type_short:"snmp_sysdesc_banner", port:port, proto:"udp" );

exit( 0 );
