# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108200");
  script_version("2025-09-09T14:09:45+0000");
  script_tag(name:"last_modification", value:"2025-09-09 14:09:45 +0000 (Tue, 09 Sep 2025)");
  script_tag(name:"creation_date", value:"2017-08-01 11:13:48 +0200 (Tue, 01 Aug 2017)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Operating System (OS) Detection (UPnP)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_dependencies("gb_upnp_udp_detect.nasl");
  script_require_udp_ports("Services/udp/upnp", 1900);
  script_mandatory_keys("upnp/identified");

  script_tag(name:"summary", value:"UPnP protocol based Operating System (OS) detection.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("os_func.inc");
include("port_service_func.inc");

SCRIPT_DESC = "Operating System (OS) Detection (UPnP)";
BANNER_TYPE = "UPnP protocol banner";

# Only covering UDP, the TCP banners are handled via sw_http_os_detection.nasl
port = service_get_port( default:1900, ipproto:"udp", proto:"upnp" );
if( ! banner = get_kb_item( "upnp/" + port + "/banner" ) ) exit( 0 );

if( "FRITZ!Box" >< banner ) {
  os_register_and_report( os:"AVM FRITZ!OS", cpe:"cpe:/o:avm:fritz%21_os", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# SERVER: FRITZ!WLAN Repeater 310 UPnP/1.0 AVM FRITZ!WLAN Repeater 310 122.07.12
# SERVER: $devicename UPnP/1.0 AVM FRITZ!WLAN Repeater 1750E 134.07.12
# nb: More detailed product / version detection in gb_avm_fritz_wlanrepeater_upnp_detect.nasl
if( "AVM FRITZ!WLAN Repeater" >< banner ) {
  os_register_and_report( os:"AVM FRITZ!WLAN Repeater", cpe:"cpe:/o:avm:fritz%21wlan_repeater", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# SERVER: VxWorks/5.4.2 UPnP/1.0 iGateway/1.1
# SERVER: vxWorks/5.5 UPnP/1.0 TL-WR820N/2.0
if( egrep( pattern:"VxWorks", string:banner, icase:TRUE ) ) {
  os_register_and_report( os:"Wind River VxWorks", cpe:"cpe:/o:windriver:vxworks", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  # nb: Don't use exit(0); here as TL-WR820N and similar banners should be detected (in the future) as well
}

# SERVER: LINUX-2.6 UPnP/1.0 MiniUPnPd/1.5
# Server: Linux/2.4.22-1.2115.nptl UPnP/1.0 miniupnpd/1.0
if( egrep( pattern:"^SERVER: Linux", string:banner, icase:TRUE ) ) {
  version = eregmatch( pattern:"Server: Linux(/|\-)([0-9.x]+)", string:banner, icase:TRUE );
  if( ! isnull( version[2] ) ) {
    os_register_and_report( os:"Linux", version:version[2], cpe:"cpe:/o:linux:kernel", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else {
    os_register_and_report( os:"Linux", cpe:"cpe:/o:linux:kernel", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  }
  exit( 0 );
}

# nb: Keep the UPnP pattern in sync with sw_http_os_detection.nasl for the TCP counterpart...

# SERVER: Ubuntu/7.10 UPnP/1.0 miniupnpd/1.0
# Server: Ubuntu/10.10 UPnP/1.0 miniupnpd/1.0
# SERVER: Ubuntu/hardy UPnP/1.0 MiniUPnPd/1.2
# SERVER: Ubuntu/lucid UPnP/1.0 MiniUPnPd/1.4
# nb: It might be possible that some of the banners below doesn't exist
# on newer or older Ubuntu versions. Still keep them in here as we can't know...
if( egrep( pattern:"^SERVER: Ubuntu", string:banner, icase:TRUE ) ) {
  version = eregmatch( pattern:"SERVER: Ubuntu/([0-9.]+)", string:banner, icase:TRUE );
  if( ! isnull( version[1] ) ) {
    os_register_and_report( os:"Ubuntu", version:version[1], cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else if( "Ubuntu/warty" >< banner ) {
    os_register_and_report( os:"Ubuntu", version:"4.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else if( "Ubuntu/hoary" >< banner ) {
    os_register_and_report( os:"Ubuntu", version:"5.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else if( "Ubuntu/breezy" >< banner ) {
    os_register_and_report( os:"Ubuntu", version:"5.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else if( "Ubuntu/dapper" >< banner ) {
    os_register_and_report( os:"Ubuntu", version:"6.06", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else if( "Ubuntu/edgy" >< banner ) {
    os_register_and_report( os:"Ubuntu", version:"6.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else if( "Ubuntu/feisty" >< banner ) {
    os_register_and_report( os:"Ubuntu", version:"7.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else if( "Ubuntu/gutsy" >< banner ) {
    os_register_and_report( os:"Ubuntu", version:"7.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else if( "Ubuntu/hardy" >< banner ) {
    os_register_and_report( os:"Ubuntu", version:"8.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else if( "Ubuntu/intrepid" >< banner ) {
    os_register_and_report( os:"Ubuntu", version:"8.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else if( "Ubuntu/jaunty" >< banner ) {
    os_register_and_report( os:"Ubuntu", version:"9.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else if( "Ubuntu/karmic" >< banner ) {
    os_register_and_report( os:"Ubuntu", version:"9.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else if( "Ubuntu/lucid" >< banner ) {
    os_register_and_report( os:"Ubuntu", version:"10.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else if( "Ubuntu/maverick" >< banner ) {
    os_register_and_report( os:"Ubuntu", version:"10.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else if( "Ubuntu/natty" >< banner ) {
    os_register_and_report( os:"Ubuntu", version:"11.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else if( "Ubuntu/oneiric" >< banner ) {
    os_register_and_report( os:"Ubuntu", version:"11.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else if( "Ubuntu/precise" >< banner ) {
    os_register_and_report( os:"Ubuntu", version:"12.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else if( "Ubuntu/quantal" >< banner ) {
    os_register_and_report( os:"Ubuntu", version:"12.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else if( "Ubuntu/raring" >< banner ) {
    os_register_and_report( os:"Ubuntu", version:"13.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else if( "Ubuntu/saucy" >< banner ) {
    os_register_and_report( os:"Ubuntu", version:"13.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else if( "Ubuntu/trusty" >< banner ) {
    os_register_and_report( os:"Ubuntu", version:"14.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else if( "Ubuntu/utopic" >< banner ) {
    os_register_and_report( os:"Ubuntu", version:"14.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else if( "Ubuntu/vivid" >< banner ) {
    os_register_and_report( os:"Ubuntu", version:"15.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else if( "Ubuntu/wily" >< banner ) {
    os_register_and_report( os:"Ubuntu", version:"15.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else if( "Ubuntu/xenial" >< banner ) {
    os_register_and_report( os:"Ubuntu", version:"16.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else if( "Ubuntu/yakkety" >< banner ) {
    os_register_and_report( os:"Ubuntu", version:"16.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else if( "Ubuntu/zesty" >< banner ) {
    os_register_and_report( os:"Ubuntu", version:"17.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else if( "Ubuntu/artful" >< banner ) {
    os_register_and_report( os:"Ubuntu", version:"17.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else if( "Ubuntu/bionic" >< banner ) {
    os_register_and_report( os:"Ubuntu", version:"18.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else if( "Ubuntu/cosmic" >< banner ) {
    os_register_and_report( os:"Ubuntu", version:"18.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else if( "Ubuntu/disco" >< banner ) {
    os_register_and_report( os:"Ubuntu", version:"19.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else if( "Ubuntu/eoan" >< banner ) {
    os_register_and_report( os:"Ubuntu", version:"19.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else if( "Ubuntu/focal" >< banner ) {
    os_register_and_report( os:"Ubuntu", version:"20.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else {
    os_register_and_report( os:"Ubuntu", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  }
  exit( 0 );
}

# Server: Debian/5.0.10 UPnP/1.0 MiniUPnPd/1.6
# Server: Debian/4.0 UPnP/1.0 miniupnpd/1.0
# Server: Debian/squeeze/sid UPnP/1.0 miniupnpd/1.0
# SERVER: Debian/wheezy/sid UPnP/1.0 MiniUPnPd/1.2
# Server: Debian/wheezy/sid UPnP/1.0 MiniUPnPd/1.6
# SERVER: Debian/lenny UPnP/1.0 MiniUPnPd/1.2
# nb: It might be possible that some of the banners below doesn't exist
# on newer or older Debian versions. Still keep them in here as we can't know...
if( egrep( pattern:"^Server: Debian", string:banner, icase:TRUE ) ) {
  version = eregmatch( pattern:"Server: Debian/([0-9.]+)", string:banner, icase:TRUE );
  if( ! isnull( version[1] ) ) {
    os_register_and_report( os:"Debian GNU/Linux", version:version[1], cpe:"cpe:/o:debian:debian_linux", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else if( "Debian/bookworm" >< banner ) {
    os_register_and_report( os:"Debian GNU/Linux", version:"12", cpe:"cpe:/o:debian:debian_linux", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else if( "Debian/bullseye" >< banner ) {
    os_register_and_report( os:"Debian GNU/Linux", version:"11", cpe:"cpe:/o:debian:debian_linux", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else if( "Debian/buster" >< banner ) {
    os_register_and_report( os:"Debian GNU/Linux", version:"10", cpe:"cpe:/o:debian:debian_linux", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else if( "Debian/stretch" >< banner ) {
    os_register_and_report( os:"Debian GNU/Linux", version:"9", cpe:"cpe:/o:debian:debian_linux", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else if( "Debian/jessie" >< banner ) {
    os_register_and_report( os:"Debian GNU/Linux", version:"8", cpe:"cpe:/o:debian:debian_linux", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else if( "Debian/wheezy" >< banner ) {
    os_register_and_report( os:"Debian GNU/Linux", version:"7", cpe:"cpe:/o:debian:debian_linux", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else if( "Debian/squeeze" >< banner ) {
    os_register_and_report( os:"Debian GNU/Linux", version:"6.0", cpe:"cpe:/o:debian:debian_linux", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else if( "Debian/lenny" >< banner ) {
    os_register_and_report( os:"Debian GNU/Linux", version:"5.0", cpe:"cpe:/o:debian:debian_linux", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else if( "Debian/etch" >< banner ) {
    os_register_and_report( os:"Debian GNU/Linux", version:"4.0", cpe:"cpe:/o:debian:debian_linux", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else if( "Debian/sarge" >< banner ) {
    os_register_and_report( os:"Debian GNU/Linux", version:"3.1", cpe:"cpe:/o:debian:debian_linux", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else if( "Debian/woody" >< banner ) {
    os_register_and_report( os:"Debian GNU/Linux", version:"3.0", cpe:"cpe:/o:debian:debian_linux", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else if( "Debian/potato" >< banner ) {
    os_register_and_report( os:"Debian GNU/Linux", version:"2.2", cpe:"cpe:/o:debian:debian_linux", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else if( "Debian/slink" >< banner ) {
    os_register_and_report( os:"Debian GNU/Linux", version:"2.1", cpe:"cpe:/o:debian:debian_linux", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else if( "Debian/hamm" >< banner ) {
    os_register_and_report( os:"Debian GNU/Linux", version:"2.0", cpe:"cpe:/o:debian:debian_linux", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else if( "Debian/bo" >< banner ) {
    os_register_and_report( os:"Debian GNU/Linux", version:"1.3", cpe:"cpe:/o:debian:debian_linux", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else if( "Debian/rex" >< banner ) {
    os_register_and_report( os:"Debian GNU/Linux", version:"1.2", cpe:"cpe:/o:debian:debian_linux", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else if( "Debian/buzz" >< banner ) {
    os_register_and_report( os:"Debian GNU/Linux", version:"1.1", cpe:"cpe:/o:debian:debian_linux", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else {
    os_register_and_report( os:"Debian GNU/Linux", cpe:"cpe:/o:debian:debian_linux", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  }
  exit( 0 );
}

# Server: CentOS/5.6 UPnP/1.0 MiniUPnPd/1.6
# Server: CentOS/6.2 UPnP/1.0 miniupnpd/1.0
# Server: CentOS/5.5 UPnP/1.0 MiniUPnPd/1.6
if( egrep( pattern:"^Server: CentOS", string:banner, icase:TRUE ) ) {
  version = eregmatch( pattern:"Server: CentOS/([0-9.]+)", string:banner, icase:TRUE );
  if( ! isnull( version[1] ) ) {
    os_register_and_report( os:"CentOS", version:version[1], cpe:"cpe:/o:centos:centos", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else {
    os_register_and_report( os:"CentOS", cpe:"cpe:/o:centos:centos", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  }
  exit( 0 );
}

# nb: More detailed OS detection in gb_huawei_ibmc_upnp_detect.nasl
if( " iBMC/" >< banner ) {
  os_register_and_report( os:"Huawei iBMC Firmware", cpe:"cpe:/o:huawei:ibmc_firmware", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# nb: More detailed OS detection in gb_loxone_miniserver_consolidation.nasl
if( egrep( pattern:"SERVER\s*:\s*Loxone Miniserver", string:banner, icase:TRUE ) ) {
  os_register_and_report( os:"Loxone Miniserver Firmware", cpe:"cpe:/o:loxone:miniserver_firmware", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# nb: Frontier Silicon based platform, most likely some embedded Linux
# SERVER: FOS/1.0 UPnP/1.0 Jupiter/6.5
if( egrep( pattern:"SERVER\s*:\s*FOS.+Jupiter", string:banner, icase:TRUE ) ) {
  os_register_and_report( os:"Linux/Unix", cpe:"cpe:/o:linux:kernel", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# TODO: There are more UPnP implementations reporting the OS:
# SERVER: FreeBSD/8.1-PRERELEASE UPnP/1.0 MiniUPnPd/1.4
# SERVER: FreeBSD/9 UPnP/1.0 MiniUPnPd/1.4
# Server: FreeBSD/8.0-RC1 UPnP/1.0 MiniUPnPd/1.2
# Server: SUSE LINUX/11.3 UPnP/1.0 miniupnpd/1.0
# Server: Fedora/8 UPnP/1.0 miniupnpd/1.0
# SERVER: Fedora/10 UPnP/1.0 MiniUPnPd/1.4

os_register_unknown_banner( banner:banner, banner_type_name:BANNER_TYPE, banner_type_short:"upnp_banner", port:port, proto:"udp" );

exit( 0 );
