# SPDX-FileCopyrightText: 2009 LSS
# SPDX-FileCopyrightText: New detection methods / pattern / code since 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.102011");
  script_version("2024-06-25T05:05:27+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-06-25 05:05:27 +0000 (Tue, 25 Jun 2024)");
  script_tag(name:"creation_date", value:"2009-09-18 16:06:42 +0200 (Fri, 18 Sep 2009)");
  script_name("SMB NativeLanMan");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2009 LSS");
  script_dependencies("cifs445.nasl", "netbios_name_get.nasl");
  script_require_ports(139, 445);

  script_tag(name:"summary", value:"It is possible to extract OS, domain and SMB server information
  from the Session Setup AndX Response packet which is generated during NTLM authentication.");

  script_tag(name:"qod_type", value:"remote_active");

  exit(0);
}

include("string_hex_func.inc");
include("smb_nt.inc");
include("global_settings.inc");
include("host_details.inc");
include("os_func.inc");
include("cpe.inc");

SCRIPT_DESC = "SMB NativeLanMan";

port = kb_smb_transport();
name = kb_smb_name(); # This is only used when talking to port 139

soc = open_sock_tcp( port );
if( ! soc ) exit( 0 );

r = smb_session_request( soc:soc, remote:name );
if( ! r ) {
  close( soc );
  exit( 0 );
}

# TODO: Implement "usesmbv1" in smb_neg_prot() and use this here (This VT needs SMBv1)
# Then we could also pass the credentials as NTLMSSP/NTLMv2 from the KB
prot = smb_neg_prot_NTLMv1( soc:soc );
if( ! prot ) {
  close( soc );
  exit( 0 );
}

cs = smb_neg_prot_cs( prot:prot );

ret = smb_session_setup_NTLMvN( soc:soc, login:"", password:"", domain:"", cs:cs, version:1 );
if( ! ret ) {
  close( soc );
  exit( 0 );
}

close( soc );

s = hexstr( ret ); # convert response packet to a "string" hex
l = strlen( s );
c = 0; # counter
out = NULL;

# according to www.snia.org/tech_activities/CIFS/CIFS-TR-1p00_FINAL.pdf
# domain, server & os info are the last 3 strings in the packet
# so there is no point in going through the whole packet

for( x = l-3; x > 0 && c < 3; x = x - 2 ) {

  if( ( s[x] + s[x-1] ) == "00" ) {
    c++;
    if( c == 1 ) {

      wg_str = hex2raw( s:out );

      if( wg_str && ! isnull( wg_str ) ) {
        set_kb_item( name:"SMB/workgroup", value:wg_str );
        set_kb_item( name:"SMB/DOMAIN", value:wg_str );
        info = "Detected SMB workgroup: " + wg_str + '\n';
        result += info;
        report = TRUE;
      }
    }

    if( c == 2 ) {

      smb_str    = hex2raw( s:out );
      smb_str_lo = tolower( smb_str );

      if( smb_str && ! isnull( smb_str ) ) {
        set_kb_item( name:"SMB/NativeLanManager", value:smb_str );
        set_kb_item( name:"SMB/SERVER", value:smb_str );
        info = "Detected SMB server: " + smb_str + '\n';
        result += info;
        report = TRUE;
      }

      if( "samba" >< smb_str_lo ) {

        version = "unknown";
        install = port + "/tcp";
        # nb: See https://www.samba.org/samba/samba/history/ for some of the possible versions
        vers = eregmatch( string:smb_str, pattern:"Samba ([0-9.]+)(a|b|c|d|p[0-9]|rc[0-9])?" );
        if( vers[1] ) {
          version = vers[1];
          if( vers[2] ) version += vers[2];
        }

        is_samba = TRUE;
        # nb: Used together with netbios_name_get.nasl (and kb_smb_is_samba) to decide if
        # Samba is installed or not without any requirement that a version exists.
        set_kb_item( name:"SMB/samba", value:TRUE );

        # nb: Used together with gb_samba_detect.nasl if the VT needs an exposed version.
        set_kb_item( name:"samba/smb_or_ssh/detected", value:TRUE );

        # nb: Used if a VT should do an active check.
        set_kb_item( name:"samba/smb/detected", value:TRUE );

        cpe = build_cpe( value:version, exp:"([0-9.]+)(a|b|c|d|p[0-9]|rc[0-9])?", base:"cpe:/a:samba:samba:" );
        if( ! cpe )
          cpe = "cpe:/a:samba:samba";

        register_product( cpe:cpe, location:install, port:port, service:"smb" );

        log_message( data:build_detection_report( app:"Samba",
                                                  version:version,
                                                  install:install,
                                                  cpe:cpe,
                                                  concluded:smb_str,
                                                  extra:result ),
                                                  port:port );
      }
    }

    if( c == 3 ) {

      os_str = hex2raw( s:out );

      if( os_str && ! isnull( os_str ) ) {

        banner_type = "SMB/Samba banner";
        os_str_lo   = tolower( os_str );

        # At least Samba 4.2.10, 4.2.14 and 4.5.8 on Debian Jessie and Stretch has an os_str of "Windows 6.1"
        # but we can identify it from the smb_str: Samba 4.2.10-Debian, Samba 4.5.8-Debian
        # Older Debian versions have "Unix" as os_str and smb_str: like Samba 3.0.20-Debian. nb: This isn't valid for at least Etch (4.0)
        # Ubuntu 17.10: os_str: Windows 6.1 smb_str: Samba 4.6.7-Ubuntu
        # The same above is also valid for SLES:
        # SLES11: os_str: Unix, smb_str: Samba 3.6.3-0.58.1-3399-SUSE-CODE11-x86_64
        # SLES12: os_str: Windows 6.1, smb_str: Samba 4.4.2-29.4-3709-SUSE-SLE_12-x86_64
        # openSUSE LEAP 42.2: os_str:  Windows 6.1, smb_str: Samba 4.4.2-11.9.1-3764-SUSE-SLE_12-x86_64
        # SLES12: os_str: Windows 6.1, smb_str: Samba 4.6.16-git.166.8fb11cda2003.43.1-SUSE-SLE_12-x86_64
        # SL12: os_str: ?; smb_str: Samba 3.6.7-48.12.1-2831-SUSE-SL12.2-x86_64

        # Those verifications were added to check and to make sure we're not jumping into the "Windows" checks later.
        # TODO: Recheck with other OS variants to apply a similar detection.
        if( is_samba || smb_str =~ "(SUSE|Debian|Ubuntu|Unix|SunOS|vxworks|Native SMB service|Linux)" || os_str == "QTS" || "Apple Base Station" >< os_str )
          linux_found = TRUE;

        banner  = '\nOS String:  ' + os_str;
        banner += '\nSMB String: ' + smb_str;
        if( "windows" >< os_str_lo && linux_found )
          banner += '\nNote: The service is running on a Linux/Unix based OS but reporting itself with an Windows related OS string.';

        if( "debian" >< smb_str_lo ) {
          # 4.2.10 was up to 8.6 and 4.2.14 was 8.7 or later
          # nb: Starting with Wheezy (7.x) we have minor releases within the version so we don't use an exact version like 7.0 as we can't differ between the OS in the banner here
          if( "Samba 4.2.10-Debian" >< smb_str || "Samba 4.2.14-Debian" >< smb_str ) {
            os_str = "Debian GNU/Linux 8";
            os_register_and_report( os:"Debian GNU/Linux", version:"8", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
          } else if( "Samba 4.5.8-Debian" >< smb_str || "Samba 4.5.12-Debian" >< smb_str || "Samba 4.5.16-Debian" >< smb_str ) {
            os_str = "Debian GNU/Linux 9";
            os_register_and_report( os:"Debian GNU/Linux", version:"9", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
          } else if( "Samba 4.9.5-Debian" >< smb_str ) {
            os_str = "Debian GNU/Linux 10";
            os_register_and_report( os:"Debian GNU/Linux", version:"10", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
          } else if( "Samba 4.13.13-Debian" >< smb_str ) {
            os_str = "Debian GNU/Linux 11";
            os_register_and_report( os:"Debian GNU/Linux", version:"11", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
          } else if( "Samba 4.17.8-Debian" >< smb_str || "Samba 4.17.12-Debian" >< smb_str ) {
            os_str = "Debian GNU/Linux 12";
            os_register_and_report( os:"Debian GNU/Linux", version:"12", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
          } else {
            os_str = "Debian GNU/Linux";
            os_register_and_report( os:"Debian GNU/Linux", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
          }
        }

        else if( "SUSE" >< smb_str ) {
          if( "CODE11" >< smb_str ) {
            os_str = "SUSE Linux Enterprise Server 11";
            os_register_and_report( os:"SUSE Linux Enterprise Server", version:"11", cpe:"cpe:/o:suse:linux_enterprise_server", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
          } else if( "SLE_12" >< smb_str ) {
            os_str = "SUSE Linux Enterprise Server 12 / openSUSE LEAP 42.2";
            os_register_and_report( os:"SUSE Linux Enterprise Server (or openSUSE LEAP 42.2)", version:"12", cpe:"cpe:/o:suse:linux_enterprise_server", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
          } else {
            sl_ver = eregmatch( pattern:"SUSE-SL([0-9.]+)", string:smb_str );
            if( sl_ver[1] ) {
              os_str = "SUSE Linux Enterprise " + sl_ver[1];
              os_register_and_report( os:"SUSE Linux Enterprise", version:sl_ver[1], cpe:"cpe:/o:suse:linux_enterprise", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
            } else {
              os_str = "Unknown SUSE Release";
              os_register_and_report( os:"Unknown SUSE Linux release", cpe:"cpe:/o:suse:unknown_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
              # nb: We want to report an unknown banner here as well to catch reports with more detailed info
              os_register_unknown_banner( banner:banner, banner_type_name:banner_type, banner_type_short:"smb_samba_banner", port:port );
            }
          }
        }

        else if( "ubuntu" >< smb_str_lo ) {
          # Warty
          if( "Samba 3.0.7-Ubuntu" >< smb_str ) {
            os_str = "Ubuntu 4.10";
            os_register_and_report( os:"Ubuntu", version:"4.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
          # Hoary
          } else if( "Samba 3.0.10-Ubuntu" >< smb_str ) {
            os_str = "Ubuntu 5.04";
            os_register_and_report( os:"Ubuntu", version:"5.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
          # Breezy
          } else if( "Samba 3.0.14a-Ubuntu" >< smb_str ) {
            os_str = "Ubuntu 5.10";
            os_register_and_report( os:"Ubuntu", version:"5.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
          # Trusty
          } else if( "Samba 4.1.6-Ubuntu" >< smb_str ) {
            os_str = "Ubuntu 14.04";
            os_register_and_report( os:"Ubuntu", version:"14.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
          # Utopic
          } else if( "Samba 4.1.11-Ubuntu" >< smb_str ) {
            os_str = "Ubuntu 14.10";
            os_register_and_report( os:"Ubuntu", version:"14.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
          # Vivid
          } else if( "Samba 4.1.13-Ubuntu" >< smb_str ) {
            os_str = "Ubuntu 15.04";
            os_register_and_report( os:"Ubuntu", version:"15.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
          # Wily
          } else if( "Samba 4.1.17-Ubuntu" >< smb_str ) {
            os_str = "Ubuntu 15.10";
            os_register_and_report( os:"Ubuntu", version:"15.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
          # Xenial
          } else if( "Samba 4.3.8-Ubuntu" >< smb_str ) {
            os_str = "Ubuntu 16.04";
            os_register_and_report( os:"Ubuntu", version:"16.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
          # Trusty and Xenial had this versions, choose the highest Ubuntu version
          } else if( "Samba 4.3.11-Ubuntu" >< smb_str || "Samba 4.3.9-Ubuntu" >< smb_str ) {
            os_str = "Ubuntu 14.04 or Ubuntu 16.04";
            os_register_and_report( os:"Ubuntu 14.04 or 16.04", cpe:"cpe:/o:canonical:ubuntu_linux:16.04", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide", full_cpe:TRUE );
          # Yakkety
          } else if( "Samba 4.4.5-Ubuntu" >< smb_str ) {
            os_str = "Ubuntu 16.10";
            os_register_and_report( os:"Ubuntu", version:"16.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
          # Zesty
          } else if( "Samba 4.5.8-Ubuntu" >< smb_str || "Samba 4.5.4-Ubuntu" >< smb_str ) {
            os_str = "Ubuntu 17.04";
            os_register_and_report( os:"Ubuntu", version:"17.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
          # Artful
          } else if( "Samba 4.6.7-Ubuntu" >< smb_str ) {
            os_str = "Ubuntu 17.10";
            os_register_and_report( os:"Ubuntu", version:"17.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
          # Bionic
          } else if( "Samba 4.7.6-Ubuntu" >< smb_str ) {
            os_str = "Ubuntu 18.04";
            os_register_and_report( os:"Ubuntu", version:"18.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
          # Cosmic
          } else if( "Samba 4.8.4-Ubuntu" >< smb_str ) {
            os_str = "Ubuntu 18.10";
            os_register_and_report( os:"Ubuntu", version:"18.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
          # Disco
          } else if( "Samba 4.10.0-Ubuntu" >< smb_str ) {
            os_str = "Ubuntu 19.04";
            os_register_and_report( os:"Ubuntu", version:"19.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
          # Eoan
          } else if( "Samba 4.10.7-Ubuntu" >< smb_str ) {
            os_str = "Ubuntu 19.10";
            os_register_and_report( os:"Ubuntu", version:"19.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
          # Focal and Impish have this version, choose the highest Ubuntu version
          } else if( "Samba 4.13.17-Ubuntu" >< smb_str ) {
            os_str = "Ubuntu 20.04 or Ubuntu 21.10";
            os_register_and_report( os:"Ubuntu 20.04 or 21.10", cpe:"cpe:/o:canonical:ubuntu_linux:21.10", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide", full_cpe:TRUE );
          # Groovy
          } else if( "Samba 4.12.5-Ubuntu" >< smb_str ) {
            os_str = "Ubuntu 20.10";
            os_register_and_report( os:"Ubuntu", version:"20.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
          # Hirsute
          } else if( "Samba 4.13.14-Ubuntu" >< smb_str ) {
            os_str = "Ubuntu 21.04";
            os_register_and_report( os:"Ubuntu", version:"21.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
          # Jammy
          } else if( "Samba 4.15.9-Ubuntu" >< smb_str || "Samba 4.15.13-Ubuntu" >< smb_str) {
            os_str = "Ubuntu 22.04";
            os_register_and_report( os:"Ubuntu", version:"22.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
          # Kinetic
          } else if( "Samba 4.16.4-Ubuntu" >< smb_str || "Samba 4.16.8-Ubuntu" >< smb_str ) {
            os_str = "Ubuntu 22.10";
            os_register_and_report( os:"Ubuntu", version:"22.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
          # Lunar
          } else if( "Samba 4.17.7-Ubuntu" >< smb_str ) {
            os_str = "Ubuntu 23.04";
            os_register_and_report( os:"Ubuntu", version:"23.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
          } else if( "Samba 4.18.6-Ubuntu" >< smb_str ) {
            os_str = "Ubuntu 23.10";
            os_register_and_report( os:"Ubuntu", version:"23.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
          } else if( "Samba 4.19.5-Ubuntu" >< smb_str ) {
            os_str = "Ubuntu 24.04";
            os_register_and_report( os:"Ubuntu", version:"24.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
          } else {
            # nb: Versions without the -Ubuntu pattern:
            # Dapper and Edgy: Samba 3.0.22
            # Feisty: Samba 3.0.24
            # Gutsy: Samba 3.0.26a
            # Hardy: Samba 3.0.28a
            # Intrepid: Samba 3.2.3
            # Jaunty: Samba 3.3.2
            # Karmic: Samba 3.4.0
            # Lucid: Samba 3.4.7
            # Maverick: Samba 3.5.4
            # Natty: Samba 3.5.8
            # Oneiric: Samba 3.5.11
            # Precise: Samba 3.6.3
            # Quantal: Samba 3.6.6
            # Raring: Samba 3.6.9
            # Saucy: Samba 3.6.18
            # nb: Starting with Utopic / 14.10 we have a -Ubuntu pattern again
            os_str = "Unknown Ubuntu Release";
            os_register_and_report( os:"Unknown Ubuntu release", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
            # nb: We want to report an unknown banner here as well to catch reports with more detailed info
            os_register_unknown_banner( banner:banner, banner_type_name:banner_type, banner_type_short:"smb_samba_banner", port:port );
          }
        }

        else if( "vxworks" >< os_str_lo ) {
          set_kb_item( name:"smb/windriver/vxworks/detected", value:TRUE );
          os_register_and_report( os:"Wind River VxWorks", cpe:"cpe:/o:windriver:vxworks", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
        }

        # OS String: QTS
        # SMB String: Samba 4.4.14
        else if( os_str == "QTS" ) {
          os_register_and_report( os:"QNAP QTS", cpe:"cpe:/o:qnap:qts", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
        }

        # OS String: Apple Base Station
        # SMB String: CIFS 4.32
        else if( "Apple Base Station" >< os_str ) {
          os_register_and_report( os:"Apple Base Station Firmware", cpe:"cpe:/o:apple:base_station_firmware", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
        }

        # OS String: SunOS 5.11 illumos-47b8d4b884
        # SMB String: Native SMB service
        else if( "SunOS" >< os_str ) {
          sun_ver = eregmatch( pattern:"SunOS ([0-9.]+)", string:os_str );
          if( sun_ver[1] ) {
            os_register_and_report( os:"SunOS", version:sun_ver[1], cpe:"cpe:/o:sun:sunos", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
          } else {
            os_register_and_report( os:"SunOS", cpe:"cpe:/o:sun:sunos", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
          }
        }

        # OS String:  Unix
        # SMB String: Samba 3.6.23-53.el6_10
        else if( "unix" >< os_str_lo && ".el" >< smb_str ) {
          version = eregmatch( pattern:"\.el([0-9]+)", string:smb_str );
          if( ! isnull( version[1] ) ) {
            os_register_and_report( os:"Red Hat Enterprise Linux / CentOS", version:version[1], cpe:"cpe:/o:redhat:enterprise_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
          } else {
            os_register_and_report( os:"Red Hat Enterprise Linux / CentOS", cpe:"cpe:/o:redhat:enterprise_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
          }
        }

        # OS String:  Unix
        # SMB String: Samba 3.0.37
        else if( "unix" >< os_str_lo || "linux" >< os_str_lo ) {
          os_register_and_report( os:"Linux/Unix", cpe:"cpe:/o:linux:kernel", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
          # nb: We want to report an unknown banner here as well to catch reports with more detailed
          # info. But also only if it contains more info and not only the Unix and Samba version string.
          if( os_str_lo != "unix" && smb_str !~ "^Samba [0-9.]+$" )
            os_register_unknown_banner( banner:banner, banner_type_name:banner_type, banner_type_short:"smb_samba_banner", port:port );
        }

        # Overwriting the "Windows 6.1" or similar OS string with Linux/Unix to not save it into the "SMB/OS" KB key later below.
        else if( "windows" >< os_str_lo && linux_found ) {
          os_str = "Linux/Unix";
          os_register_and_report( os:os_str, cpe:"cpe:/o:linux:kernel", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );

          # nb: We want to report an unknown banner here as well to catch reports with more detailed info
          # nb: Also only report if the banner is not Samba or Samba without a generic version like e.g. Samba 4.10.6 or Samba 3.0.26a
          if( ! eregmatch( string:smb_str, pattern:"^Samba ([0-9.]+)(a|b|c|d|p[0-9]|rc[0-9])?$", icase:FALSE ) )
            os_register_unknown_banner( banner:banner, banner_type_name:banner_type, banner_type_short:"smb_samba_banner", port:port );
        }

        # nb: Note the comments about some Linux/Unix SMB installations reporting a "Windows String"
        else if( "windows" >< os_str_lo && ! linux_found ) {

          #Example strings:
          #smb_str: Windows 10 Pro 6.3, os_str: Windows 10 Pro 10586
          #smb_str: Windows 10 Home 6.3, os_str: Windows 10 Home 10586
          #smb_str: Windows 2000 LAN Manager, os_str: Windows 5.1 -> Windows XP SP3, 32bit, German
          #smb_str: Windows 7 Enterprise 6.1, os_str: Windows 7 Enterprise 7601 Service Pack 1
          #smb_str: Windows 7 Enterprise 6.1, os_str: Windows 7 Enterprise 7600 -> No Service Pack
          #smb_str: Windows Server 2008 R2 Datacenter 6.1, os_str: Windows Server 2008 R2 Datacenter 7601 Service Pack 1
          #smb_str: Windows XP 5.2, os_str: Windows XP 3790 Service Pack 2 -> Windows XP SP2, 64bit
          #smb_str: Windows Server 2016 Standard 6.3, os_str: Windows Server 2016 Standard 14393
          #smb_str: Windows 10 Enterprise 2016 LTSB 6.3, os_str: Windows 10 Enterprise 2016 LTSB 14393
          #smb_str: Windows 10 Enterprise 6.3, os_str: Windows 10 Enterprise 22000
          #n.b. Filter out the build version from os_str to identify Windows 11 systems
          build = eregmatch(string:os_str_lo, pattern:"[0-9]{5}");
          if(max_index(build) == 1) {
            build = build[0];
          } else {
            build = 0;
          }
          if( "windows 10 " >< os_str_lo && build >= 22000 ) {
            cpe = "cpe:/o:microsoft:windows_11";

            if( ver = get_version_from_build( string:os_str, win_name:"win11" ) )
              cpe += ":" + tolower( ver );
            else
              cpe += ":";

            if( "ltsb" >< os_str_lo )
              cpe += ":ltsb";
            else if( "ltsc" >< os_str_lo )
              cpe += ":ltsc";
            else
              cpe += ":cb";

            if( "enterprise" >< os_str_lo )
              cpe += ":enterprise";
            else if( "education" >< os_str_lo )
              cpe += ":education";
            else if( "home" >< os_str_lo )
              cpe += ":home";
            else if( "pro" >< os_str_lo )
              cpe += ":pro";
            else
              cpe += ":unknown_edition";

            # nb: os_str still contains "Windows 10" on Windows 11 (because given like this from the response)
            # so we need to rewrite this here before passing the info to the user.
            os_str = str_replace( string:os_str, find:"Windows 10", replace:"Windows 11" );

            os_register_and_report( os:os_str, version:ver, cpe:cpe, full_cpe:TRUE, banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
          }

          #smb_str: Windows Server 2022 Standard 6.3, os_str: Windows Server 2022 Standard 20348
          else if( "windows server 2022" >< os_str_lo ) {
            cpe = "cpe:/o:microsoft:windows_server_2022";
            cpe += "::";

            if( "datacenter" >< os_str_lo )
              cpe += ":datacenter";
            else if( "standard" >< os_str_lo )
              cpe += ":standard";
            else if ("azure" >< os_str_lo )
              cpe += ":azure";
            else
              cpe += ":unknown_edition";

            os_register_and_report( os:os_str, version:ver, cpe:cpe, full_cpe:TRUE, banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
          }

          else if( "windows 10 " >< os_str_lo ) {
            cpe = "cpe:/o:microsoft:windows_10";

            if( ver = get_version_from_build( string:os_str, win_name:"win10" ) )
              cpe += ":" + tolower( ver );
            else
              cpe += ":";

            if( "ltsb" >< os_str_lo )
              cpe += ":ltsb";
            else if( "ltsc" >< os_str_lo )
              cpe += ":ltsc";
            else
              cpe += ":cb";

            if( "enterprise" >< os_str_lo )
              cpe += ":enterprise";
            else if( "education" >< os_str_lo )
              cpe += ":education";
            else if( "home" >< os_str_lo )
              cpe += ":home";
            else if( "pro" >< os_str_lo )
              cpe += ":pro";
            else
              cpe += ":unknown_edition";

            os_register_and_report( os:os_str, version:ver, cpe:cpe, full_cpe:TRUE, banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
          }

          #smb_str: Windows Server 2019 Datacenter 6.3, os_str: Windows Server 2019 Datacenter 17763
          else if( "windows server 2019" >< os_str_lo ) {
            cpe = "cpe:/o:microsoft:windows_server_2019";

            if( ver = get_version_from_build( string:os_str, win_name:"win10" ) )
              cpe += ":" + tolower( ver ) + ":";
            else
              cpe += "::";

            if( "datacenter" >< os_str_lo )
              cpe += ":datacenter";
            else if( "standard" >< os_str_lo )
              cpe += ":standard";
            else
              cpe += ":unknown_edition";

            os_register_and_report( os:os_str, version:ver, cpe:cpe, full_cpe:TRUE, banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
          }

          else if( "windows embedded" >< os_str_lo ) {

            cpe = "cpe:/o:microsoft:windows_embedded";

            if( "8.1" >< os_str_lo )
              cpe += "_8.1:";
            else if( "7601" >< os_str_lo )
              cpe += "_7:-:sp1:";
            else if( "7600" >< os_str_lo )
              cpe += "_7:-:-:";
            else
              cpe += ":-:-:";

            # https://en.wikipedia.org/wiki/Windows_IoT#Embedded_family
            if( "compact" >< os_str_lo )
              cpe += "compact";
            else if( "standard" >< os_str_lo )
              cpe += "standard";
            else if( "enterprise" >< os_str_lo )
              cpe += "enterprise";
            else if( "server" >< os_str_lo )
              cpe += "server";
            else if( "industry" >< os_str_lo )
              cpe += "industry";
            else if( "navready" >< os_str_lo )
              cpe += "navready";
            else if( "automotive" >< os_str_lo )
              cpe += "automotive";
            else if( "handheld" >< os_str_lo )
              cpe += "handheld";
            else if( "pro" >< os_str_lo )
              cpe += "pro";

            os_register_and_report( os:os_str, cpe:cpe, banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
          } else if( "windows 5.1" >< os_str_lo && "windows 2000 lan manager" >< smb_str_lo ) {
            os_register_and_report( os:"Windows XP", cpe:"cpe:/o:microsoft:windows_xp", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
          } else if( "windows 5.0" >< os_str_lo && "windows 2000 lan manager" >< smb_str_lo ) {
            os_register_and_report( os:"Windows 2000", cpe:"cpe:/o:microsoft:windows_2000", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
          } else if( "windows xp 5.2" >< smb_str_lo && "service pack 2" >< os_str_lo ) {
            os_register_and_report( os:os_str, cpe:"cpe:/o:microsoft:windows_xp:-:sp2:x64", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
          } else if( "windows xp 5.2" >< smb_str_lo ) {
            os_register_and_report( os:os_str, cpe:"cpe:/o:microsoft:windows_xp:-:-:x64", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
          } else if( "windows vista" >< os_str_lo && "service pack 1" >< os_str_lo ) {
            os_register_and_report( os:os_str, cpe:"cpe:/o:microsoft:windows_vista:-:sp1", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
          } else if( "windows vista" >< os_str_lo && "service pack 2" >< os_str_lo ) {
            os_register_and_report( os:os_str, cpe:"cpe:/o:microsoft:windows_vista:-:sp2", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
          } else if( "windows vista " >< os_str_lo ) {
            os_register_and_report( os:os_str, cpe:"cpe:/o:microsoft:windows_vista", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
          } else if( "windows 7 " >< os_str_lo && ( "service pack 1" >< os_str_lo || "7601" >< os_str ) ) {
            os_register_and_report( os:os_str, cpe:"cpe:/o:microsoft:windows_7:-:sp1", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
          } else if( "windows 7 " >< os_str_lo && "7600" >< os_str ) {
            os_register_and_report( os:os_str, cpe:"cpe:/o:microsoft:windows_7:-:-:", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
          } else if( "windows 7 " >< os_str_lo ) {
            os_register_and_report( os:os_str, cpe:"cpe:/o:microsoft:windows_7", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
          } else if( "windows 8.1 " >< os_str_lo ) {
            os_register_and_report( os:os_str, cpe:"cpe:/o:microsoft:windows_8.1", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
          } else if( "windows 8 " >< os_str_lo ) {
            os_register_and_report( os:os_str, cpe:"cpe:/o:microsoft:windows_8", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
          } else if( "windows server 2003 " >< os_str_lo && "service pack 1" >< os_str_lo ) {
            os_register_and_report( os:os_str, cpe:"cpe:/o:microsoft:windows_server_2003:-:sp1", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
          } else if( "windows server 2003 " >< os_str_lo && "service pack 2" >< os_str_lo ) {
            os_register_and_report( os:os_str, cpe:"cpe:/o:microsoft:windows_server_2003:-:sp2", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
          } else if( "windows server 2003 " >< os_str_lo ) {
            os_register_and_report( os:os_str, cpe:"cpe:/o:microsoft:windows_server_2003", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
          } else if( "windows server 2008 " >< os_str_lo && "service pack 1" >< os_str_lo && "r2" >< os_str_lo ) {
            os_register_and_report( os:os_str, cpe:"cpe:/o:microsoft:windows_server_2008:r2:sp1", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
          } else if( "windows server 2008 " >< os_str_lo && "r2" >< os_str_lo ) {
            os_register_and_report( os:os_str, cpe:"cpe:/o:microsoft:windows_server_2008:r2", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
          } else if( "windows server (r) 2008 " >< os_str_lo && "service pack 2" >< os_str_lo ) {
            os_register_and_report( os:os_str, cpe:"cpe:/o:microsoft:windows_server_2008:-:sp2", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
          } else if( "windows server (r) 2008 " >< os_str_lo && "service pack 1" >< os_str_lo ) {
            os_register_and_report( os:os_str, cpe:"cpe:/o:microsoft:windows_server_2008:-:sp1", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
          } else if( "windows server (r) 2008 " >< os_str_lo || "windows server 2008 " >< os_str_lo ) {
            os_register_and_report( os:os_str, cpe:"cpe:/o:microsoft:windows_server_2008", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
          # OS String: Windows Server 2012 Datacenter 9200; SMB String: Windows Server 2012 Datacenter 6.2
          } else if( "windows server 2012 " >< os_str_lo ) {
            os_register_and_report( os:os_str, cpe:"cpe:/o:microsoft:windows_server_2012", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
          } else if( "windows server 2016 " >< os_str_lo ) {
            os_register_and_report( os:os_str, cpe:"cpe:/o:microsoft:windows_server_2016", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
          } else {
            os_register_unknown_banner( banner:banner, banner_type_name:SCRIPT_DESC, port:port, banner_type_short:"smb_nativelanman_banner" );
            os_register_and_report( os:os_str, cpe:"cpe:/o:microsoft:windows", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
          }
        }

        else {
          os_register_unknown_banner( banner:banner, banner_type_name:banner_type, banner_type_short:"smb_samba_banner", port:port );
        }

        set_kb_item( name:"Host/OS/smb", value:os_str );
        set_kb_item( name:"SMB/OS", value:os_str );
        info = "Detected OS: "+ os_str + '\n';
        result += info;
        report = TRUE;
      }

      if( report_verbosity && report ) {
        log_message( port:port, data:result );
      }
    }
    out = NULL;
  } else {
    out = s[x-1] + s[x] + out;
  }
}

if( banner ) {
  banner = ereg_replace( string:banner, pattern:'^([\n\r ]+)', replace:"" );
  set_kb_item( name:"smb/native_lanman/full_banner", value:TRUE );
  set_kb_item( name:"smb/native_lanman/" + port + "/full_banner", value:chomp( banner ) );
}

exit( 0 );
