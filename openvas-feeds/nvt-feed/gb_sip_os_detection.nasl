# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108201");
  script_version("2025-02-11T05:38:07+0000");
  script_tag(name:"last_modification", value:"2025-02-11 05:38:07 +0000 (Tue, 11 Feb 2025)");
  script_tag(name:"creation_date", value:"2017-08-01 11:13:48 +0200 (Tue, 01 Aug 2017)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Operating System (OS) Detection (SIP)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_dependencies("sip_detection.nasl", "sip_detection_tcp.nasl");
  script_mandatory_keys("sip/detected");

  script_tag(name:"summary", value:"SIP banner based Operating System (OS) detection.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("os_func.inc");
include("sip.inc");
include("misc_func.inc");
include("port_service_func.inc");

SCRIPT_DESC = "Operating System (OS) Detection (SIP)";
BANNER_TYPE = "SIP server banner";

infos = sip_get_port_proto( default_port:"5060", default_proto:"udp" );
port  = infos["port"];
proto = infos["proto"];

# nb: sip_get_banner is setting the full banner below if it has detected a SIP service.
# We just want to call it here so that this script can run "standalone".
sip_get_banner( port:port, proto:proto );
if( ! full_banner = get_kb_item( "sip/full_banner/" + proto + "/" + port ) )
  exit( 0 );

serverbanner = get_kb_item( "sip/server_banner/" + proto + "/" + port );
if( serverbanner )
  concluded = "Server Banner: " + serverbanner;

uabanner = get_kb_item( "sip/useragent_banner/" + proto + "/" + port );
if( uabanner ) {
  if( concluded )
    concluded += '\n';
  concluded = "User-Agent Banner: " + uabanner;
}

if( serverbanner ) {

  # Server: snom
  # nb: Older firmware versions had something like (see gb_snom_detect.nasl):
  # "Server: snom300/1.2.3
  # "Server: snom/1.2.3
  if( "snom" >< serverbanner ) {
    os_register_and_report( os:"Linux", cpe:"cpe:/o:linux:kernel", banner_type:BANNER_TYPE, port:port, proto:proto, banner:concluded, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  # nb: Starting with Wheezy (7.x) we have minor releases within the version so we don't use an exact version like 7.0 as we can't differ between the OS in the banner here
  if( "+deb12" >< serverbanner ) {
    os_register_and_report( os:"Debian GNU/Linux", version:"12", cpe:"cpe:/o:debian:debian_linux", banner_type:BANNER_TYPE, port:port, proto:proto, banner:concluded, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "+deb11" >< serverbanner ) {
    os_register_and_report( os:"Debian GNU/Linux", version:"11", cpe:"cpe:/o:debian:debian_linux", banner_type:BANNER_TYPE, port:port, proto:proto, banner:concluded, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "+deb10" >< serverbanner ) {
    os_register_and_report( os:"Debian GNU/Linux", version:"10", cpe:"cpe:/o:debian:debian_linux", banner_type:BANNER_TYPE, port:port, proto:proto, banner:concluded, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "+deb9" >< serverbanner ) {
    os_register_and_report( os:"Debian GNU/Linux", version:"9", cpe:"cpe:/o:debian:debian_linux", banner_type:BANNER_TYPE, port:port, proto:proto, banner:concluded, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "+deb8" >< serverbanner ) {
    os_register_and_report( os:"Debian GNU/Linux", version:"8", cpe:"cpe:/o:debian:debian_linux", banner_type:BANNER_TYPE, port:port, proto:proto, banner:concluded, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "~dfsg" >< serverbanner ) {
    os_register_and_report( os:"Debian GNU/Linux", cpe:"cpe:/o:debian:debian_linux", banner_type:BANNER_TYPE, port:port, proto:proto, banner:concluded, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  # e.g. Server:Microsoft-Windows-NT/5.1 UPnP/1.0 UPnP-Device-Host/1.0
  if( "Microsoft-Windows" >< serverbanner ) {
    os_register_and_report( os:"Microsoft Windows", cpe:"cpe:/o:microsoft:windows", banner_type:BANNER_TYPE, port:port, proto:proto, banner:concluded, desc:SCRIPT_DESC, runs_key:"windows" );
    exit( 0 );
  }

  # e.g.
  # Server: kamailio (4.0.1 (sparc/solaris))
  # Server: kamailio (4.2.3 (x86_64/linux))
  # Server: Kamailio (1.5.4-notls (i386/linux))
  # Server: kamailio (3.3.1 (x86_64/freebsd))
  if( "kamailio" >< tolower( serverbanner ) ) {

    if( "/linux))" >< serverbanner ) {
      os_register_and_report( os:"Linux", cpe:"cpe:/o:linux:kernel", banner_type:BANNER_TYPE, port:port, proto:proto, banner:concluded, desc:SCRIPT_DESC, runs_key:"unixoide" );
      exit( 0 );
    }

    if( "/solaris))" >< serverbanner ) {
      os_register_and_report( os:"Sun Solaris", cpe:"cpe:/o:sun:solaris", banner_type:BANNER_TYPE, port:port, proto:proto, banner:concluded, desc:SCRIPT_DESC, runs_key:"unixoide" );
      exit( 0 );
    }

    if( "/freebsd))" >< serverbanner ) {
      os_register_and_report( os:"FreeBSD", cpe:"cpe:/o:freebsd:freebsd", banner_type:BANNER_TYPE, port:port, proto:proto, banner:concluded, desc:SCRIPT_DESC, runs_key:"unixoide" );
      exit( 0 );
    }

    if( "/openbsd))" >< serverbanner ) {
      os_register_and_report( os:"OpenBSD", cpe:"cpe:/o:openbsd:openbsd", banner_type:BANNER_TYPE, port:port, proto:proto, banner:concluded, desc:SCRIPT_DESC, runs_key:"unixoide" );
      exit( 0 );
    }
  }

  # nb: More detailed OS detection in gb_grandstream_ucm_consolidation.nasl
  if( "Grandstream UCM" >< serverbanner ) {
    os_register_and_report( os:"Grandstream UCM Firmware", cpe:"cpe:/o:grandstream:ucm_firmware", banner_type:BANNER_TYPE, port:port, proto:proto, banner:concluded, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  # nb: More detailed detection in gsf/gb_barracuda_cloudgen_firewall_sip_detect.nasl
  if( "Barracuda CloudGen Firewall" >< serverbanner ) {
    os_register_and_report( os:"Barracuda CloudGen Firewall Firmware", cpe:"cpe:/o:barracuda:cloudgen_firewall_firmware", banner_type:BANNER_TYPE, port:port, proto:proto, banner:concluded, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  # e.g.:
  # RTCC/5.0.0.0 MSExchangeUM/15.01.2507.017
  if( "MSExchangeUM" >< serverbanner ) {
    os_register_and_report( os:"Microsoft Windows", cpe:"cpe:/o:microsoft:windows", banner_type:BANNER_TYPE, port:port, proto:proto, banner:concluded, desc:SCRIPT_DESC, runs_key:"windows" );
    exit( 0 );
  }

  # e.g.:
  # Cisco/SPA303-7.4.8a
  # Cisco/SPA122-1.4.1(SR5)
  # Cisco/SPA504G-7.6.2c
  # nb: More detailed detection in gb_cisco_spa_voip_device_sip_detect.nasl
  if( "Cisco/SPA" >< serverbanner ) {
    os_register_and_report( os:"Cisco SPA Firmware", cpe:"cpe:/o:cisco:spa_firmware", banner_type:BANNER_TYPE, port:port, proto:proto, banner:concluded, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  # Server: Grandstream GXP1625 1.0.2.25
  #
  # nb: More detailed detection in gb_grandstream_gxp_sip_detect.nasl
  if( serverbanner =~ "Grandstream GXP" ) {
    os_register_and_report( os:"Grandstream GXP Firmware", cpe:"cpe:/o:grandstream:gxp_firmware", banner_type:BANNER_TYPE, port:port, proto:proto, banner:concluded, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  # Server: Mitel 6930/6.4.0.132
  # Server: Aastra 6731i/3.2.2.3077
  #
  # nb: More detailed detection in gsf/gb_mitel_ip_phones_sip_detect.nasl
  if( serverbanner =~ "(Mitel|Aastra) [0-9]{4}" ) {
    os_register_and_report( os:"Mitel IP Phone Firmware", cpe:"cpe:/o:mitel:sip_firmware", banner_type:BANNER_TYPE, port:port, proto:proto, banner:concluded, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  # Mediant VE SBC/v.7.20A.254.202
  # Audiocodes-Sip-Gateway-Mediant 600/v.6.20A.045.001
  #
  # nb: More detailed detection in gsf/gb_audiocodes_sbc_sip_detect.nasl
  if( serverbanner =~ "^(Audiocodes-Sip-Gateway-)?Mediant[^/]+/v\." ) {
    os_register_and_report( os:"AudioCodes Mediant Firmware", cpe:"cpe:/o:audiocodes:mediant_firmware", banner_type:BANNER_TYPE, port:port, proto:proto, banner:concluded, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }
}

if( uabanner ) {

  # User-Agent: AVM FRITZ!Box Fon WLAN 7170 29.04.88 (Feb  9 2014)
  # User-Agent: FRITZ!OS
  if( "FRITZ!OS" >< uabanner || "AVM FRITZ" >< uabanner ) {
    os_register_and_report( os:"AVM FRITZ!OS", cpe:"cpe:/o:avm:fritz%21_os", banner_type:BANNER_TYPE, port:port, proto:proto, banner:concluded, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  # e.g. User-Agent: P3/v9.1.3.1590 QT/5.7.1 Xyclops/v2.7.5-r16845 OS/Windows 8 Network/Wi-Fi
  if( "OS/Windows" >< uabanner ) {
    if( "OS/Windows 7" >< uabanner ) {
      os_register_and_report( os:"Microsoft Windows 7", cpe:"cpe:/o:microsoft:windows_7", banner_type:BANNER_TYPE, port:port, proto:proto, banner:concluded, desc:SCRIPT_DESC, runs_key:"windows" );
    } else if( "OS/Windows 8.1" >< uabanner ) {
      os_register_and_report( os:"Microsoft Windows 8.1", cpe:"cpe:/o:microsoft:windows_8.1", banner_type:BANNER_TYPE, port:port, proto:proto, banner:concluded, desc:SCRIPT_DESC, runs_key:"windows" );
    } else if( "OS/Windows 8" >< uabanner ) {
      os_register_and_report( os:"Microsoft Windows 8", cpe:"cpe:/o:microsoft:windows_8", banner_type:BANNER_TYPE, port:port, proto:proto, banner:concluded, desc:SCRIPT_DESC, runs_key:"windows" );
    } else if( "OS/Windows 10" >< uabanner ) {
      os_register_and_report( os:"Microsoft Windows 10", cpe:"cpe:/o:microsoft:windows_10", banner_type:BANNER_TYPE, port:port, proto:proto, banner:concluded, desc:SCRIPT_DESC, runs_key:"windows" );
    } else {
      os_register_and_report( os:"Microsoft Windows", cpe:"cpe:/o:microsoft:windows", banner_type:BANNER_TYPE, port:port, proto:proto, banner:concluded, desc:SCRIPT_DESC, runs_key:"windows" );
      # nb: Also register an unknown banner so we can update the ones above
      os_register_unknown_banner( banner:uabanner, banner_type_name:BANNER_TYPE, banner_type_short:"sip_banner", port:port, proto:proto );
    }
    exit( 0 );
  }

  # e.g. User-Agent: Alcatel-Lucent 8460 ACS 12.0.2b0290
  # According to some docs the base OS is Red Hat but using Linux/Unix for now
  if( "Alcatel-Lucent" >< uabanner && "ACS" >< uabanner ) {
    os_register_and_report( os:"Linux/Unix", cpe:"cpe:/o:linux:kernel", banner_type:BANNER_TYPE, port:port, proto:proto, banner:concluded, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  # e.g. User-Agent: (XMCDVUA v2.2.1b90q_pj22 System[Linux-3.10/armv7l] Make[QUANTA] Model[QTAQZ3] OS[5.1.1] InternetMode[WIFI] Ver[6.6.1] State[])
  if( "System[Linux" >< uabanner ) {
    version = eregmatch( pattern:"System\[Linux-([0-9.]+)", string:uabanner );
    if( ! isnull( version[1] ) ) {
      os_register_and_report( os:"Linux", version:version[1], cpe:"cpe:/o:linux:kernel", banner_type:BANNER_TYPE, port:port, proto:proto, banner:concluded, desc:SCRIPT_DESC, runs_key:"unixoide" );
    } else {
      os_register_and_report( os:"Linux", cpe:"cpe:/o:linux:kernel", banner_type:BANNER_TYPE, port:port, proto:proto, banner:concluded, desc:SCRIPT_DESC, runs_key:"unixoide" );
    }
    exit( 0 );
  }

  # User-Agent: IceWarp SIP 12.0.3.1 RHEL6 x64
  # User-Agent: IceWarp SIP 12.0.4.0 DEB8 x64
  # User-Agent: IceWarp SIP 12.0.2.1 x64
  # User-Agent: IceWarp SIP 12.0.3.1
  # User-Agent: IceWarp SIP 12.1.1.0 RC24 RHEL7 x64
  # User-Agent: IceWarp SIP 12.0.4.0 UBUNTU1404 x64
  # User-Agent: IceWarp SIP 12.1.2.0 (2018-05-03) RHEL6 x64
  if( "IceWarp SIP" >< uabanner ) {
    if( os_info = eregmatch( pattern:"IceWarp SIP ([0-9.]+) ([^ ]+) ([^ ]+)( [^ ]+)?", string:uabanner, icase:FALSE ) ) {
      if( max_index( os_info ) == 5 ) {
        offset = 1;
      } else {
        offset = 0;
      }
      if( "RHEL" >< os_info[2+offset] ) {
        version = eregmatch( pattern:"RHEL([0-9.]+)", string:os_info[2+offset] );
        if( ! isnull( version[1] ) ) {
          os_register_and_report( os:"Red Hat Enterprise Linux", version:version[1], cpe:"cpe:/o:redhat:enterprise_linux", banner_type:BANNER_TYPE, port:port, proto:proto, banner:concluded, desc:SCRIPT_DESC, runs_key:"unixoide" );
        } else {
          os_register_and_report( os:"Red Hat Enterprise Linux", cpe:"cpe:/o:redhat:enterprise_linux", banner_type:BANNER_TYPE, port:port, proto:proto, banner:concluded, desc:SCRIPT_DESC, runs_key:"unixoide" );
        }
        exit( 0 );
      } else if( "DEB" >< os_info[2+offset] ) {
        version = eregmatch( pattern:"DEB([0-9.]+)", string:os_info[2+offset] );
        if( ! isnull( version[1] ) ) {
          os_register_and_report( os:"Debian GNU/Linux", version:version[1], cpe:"cpe:/o:debian:debian_linux", banner_type:BANNER_TYPE, port:port, proto:proto, banner:concluded, desc:SCRIPT_DESC, runs_key:"unixoide" );
        } else {
          os_register_and_report( os:"Debian GNU/Linux", cpe:"cpe:/o:debian:debian_linux", banner_type:BANNER_TYPE, port:port, proto:proto, banner:concluded, desc:SCRIPT_DESC, runs_key:"unixoide" );
        }
        exit( 0 );
      } else if( "UBUNTU" >< os_info[2+offset] ) {
        version = eregmatch( pattern:"UBUNTU([0-9.]+)", string:os_info[2+offset] );
        if( ! isnull( version[1] ) ) {
          version = ereg_replace( pattern:"^([0-9]{1,2})(04|10)$", string:version[1], replace:"\1.\2" );
          os_register_and_report( os:"Ubuntu", version:version, cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, proto:proto, banner:concluded, desc:SCRIPT_DESC, runs_key:"unixoide" );
        } else {
          os_register_and_report( os:"Ubuntu", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, proto:proto, banner:concluded, desc:SCRIPT_DESC, runs_key:"unixoide" );
        }
        exit( 0 );
      }
      # nb: No exit here as we want to report an unknown OS later...
    } else {
      exit( 0 ); # No OS info so just skip this IceWarp banner...
    }
  }

  # User-Agent: LANCOM 1781VA (over ISDN) / 9.04.0184 / 23.03.2015
  # User-Agent: LANCOM R884VA (over ISDN) / 9.24.0191 / 02.02.2017
  # User-Agent: LANCOM 1781A / 9.10.0333 / 14.07.2015
  # nb: More detailed detection in gb_lancom_devices_sip_detect.nasl
  if( "LANCOM " >< uabanner ) {
    os_register_and_report( os:"LANCOM Firmware", cpe:"cpe:/o:lancom:lancom_firmware", banner_type:BANNER_TYPE, port:port, proto:proto, banner:concluded, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  # User-Agent: Auerswald COMpact 4000 sofia-sip/1.12.11
  # nb: More detailed detection in gsf/gb_auerswald_compact_consolidation.nasl
  if( uabanner =~ "Auerswald COMpact" ) {
    os_register_and_report( os:"Auerswald COMpact Firmware", cpe:"cpe:/o:auerswald:compact_firmware", banner_type:BANNER_TYPE, port:port, proto:proto, banner:concluded, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  # User-Agent: Auerswald COMmander 6000 sofia-sip/1.12.11
  # nb: More detailed detection in gsf/gb_auerswald_commander_consolidation.nasl
  if( uabanner =~ "Auerswald COMmander" ) {
    os_register_and_report( os:"Auerswald COMmander Firmware", cpe:"cpe:/o:auerswald:comander_firmware", banner_type:BANNER_TYPE, port:port, proto:proto, banner:concluded, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  # User-Agent: Grandstream GXP1400 1.0.4.13
  # User-Agent: Grandstream GXP1450 1.0.3.30
  #
  # nb: More detailed detection in gb_grandstream_gxp_sip_detect.nasl
  if( uabanner =~ "Grandstream GXP" ) {
    os_register_and_report( os:"Grandstream GXP Firmware", cpe:"cpe:/o:grandstream:gxp_firmware", banner_type:BANNER_TYPE, port:port, proto:proto, banner:concluded, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  # User-Agent: Cisco ATA 186  v3.1.0 atasip (040211A)
  # Server: Cisco-ATA191-MPP/11-1-0MSR3-9
  # nb: More detailed detection in gb_cisco_ata_sip_detect.nasl
  if( uabanner =~ "Cisco[- ]ATA ?[0-9]{3}" || serverbanner =~ "Cisco[- ]ATA ?[0-9]{3}" ) {
    os_register_and_report( os:"Cisco ATA Analog Telephone Adapter Firmware", cpe:"cpe:/o:cisco:ata_analog_telephone_adapter_firmware", banner_type:BANNER_TYPE, port:port, proto:proto, banner:concluded, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  # User-Agent: Yealink SIP-T21P_E2 52.83.0.35
  # User-Agent: Yealink W60B 77.83.0.85
  # User-Agent: Yealink VC800 63.345.0.40
  # nb: More detailed detection in gb_yealink_ip_phone_sip_detect.nasl
  if( uabanner =~ "Yealink " ) {
    os_register_and_report( os:"Yealink IP Phone Firmware", cpe:"cpe:/o:yealink:voip_phone_firmware", banner_type:BANNER_TYPE, port:port, proto:proto, banner:concluded, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  # e.g.:
  # User-Agent: PolycomVVX-VVX_250-UA/6.4.3.5156
  # nb: More detailed detection in gsf/gb_polycom_vvx_sip_detect.nasl
  if( "PolycomVVX" >< uabanner ) {
    os_register_and_report( os:"Polycom Unified Communications Software", cpe:"cpe:/o:polycom:unified_communications_software", banner_type:BANNER_TYPE, port:port, proto:proto, banner:concluded, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

}

# Not detailed enough, could be anything. e.g.:
# RTCC/5.0.0.0
if( egrep( pattern:"^RTCC(/[0-9.]+)?$", string:serverbanner, icase:FALSE ) )
  exit( 0 );

# The PBX is running / supported on at least Windows and Linux
# Server: 3CX
# User-Agent: 3CXPhoneSystem 15.5.15502.6 (15502)
if( serverbanner == "3CX" || "3CXPhoneSystem" >< uabanner )
  exit( 0 );

os_register_unknown_banner( banner:full_banner, banner_type_name:BANNER_TYPE, banner_type_short:"sip_banner", port:port, proto:proto );

exit( 0 );
