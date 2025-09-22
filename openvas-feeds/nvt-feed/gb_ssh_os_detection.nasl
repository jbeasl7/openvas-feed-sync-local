# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105586");
  script_version("2025-04-25T05:39:37+0000");
  script_tag(name:"last_modification", value:"2025-04-25 05:39:37 +0000 (Fri, 25 Apr 2025)");
  script_tag(name:"creation_date", value:"2016-03-23 14:28:40 +0100 (Wed, 23 Mar 2016)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Operating System (OS) Detection (SSH Banner)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("ssh_detect.nasl");
  script_require_ports("Services/ssh", 22);
  script_mandatory_keys("ssh/server_banner/available");

  script_tag(name:"summary", value:"SSH banner-based Operating System (OS) detection.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("ssh_func.inc");
include("host_details.inc");
include("os_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

SCRIPT_DESC = "Operating System (OS) Detection (SSH Banner)";
BANNER_TYPE = "SSH banner";

port = ssh_get_port( default:22 );
banner = ssh_get_serverbanner( port:port );
if( ! banner  || banner == "" || isnull( banner ) )
  exit( 0 );

login_banner = ssh_get_login_banner( port:port );

# Dell EMC Networking Operating System (OS10)
if( login_banner =~ "Dell EMC Networking Operating System \(OS10\)" )
{
  os_register_and_report( os:"Dell EMC SmartFabric OS10", cpe:"cpe:/o:dell:emc_networking_os10", banner_type:BANNER_TYPE, port:port, banner:login_banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# Vega Session Controller - 2.3.23-119 (GA)
if( "Vega Session Controller" >< login_banner )
{
  os_register_and_report( os:"Sangoma Session Border Controller (SBC) Firmware", cpe:"cpe:/o:sangoma:session_border_controller_firmware", banner_type:BANNER_TYPE, port:port, banner:login_banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# Space release 20.1R1.2 (393060)
else if( login_banner =~ "^Space release" )
{
  os_register_and_report( os:"Juniper Networks Junos Space", cpe:"cpe:/o:juniper:junos_space", banner_type:BANNER_TYPE, port:port, banner:login_banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# nb: Generic banner without OS info covered by gb_dropbear_ssh_detect.nasl
if( egrep( pattern:"^SSH-([0-9.]+)-dropbear[_-]([0-9.]+)$", string:banner ) ||
    banner == "SSH-2.0-dropbear" ) {
  exit( 0 );
}

# nb: Supports Linux, UNIX, BSD, Solaris, OS/2 and Windows so exit for a generic banner without OS info...
if( banner =~ "^SSH-2.0-libssh[_-][0-9.]+$" ||
    banner == "SSH-2.0-libssh" ) {
  exit( 0 );
}

# No OS info...
if( banner == "SSH-2.0-SSH_2.0" )
  exit( 0 );

# Vendor: "Works with any OS vendor and will function without an OS if needed"
if( egrep( pattern:"^SSH-2\.0-RomSShell_[0-9.]+$", string:banner ) ||
    banner == "SSH-2.0-RomSShell" )
  exit( 0 );

# Cross-platform / platform independent
if( banner == "SSH-2.0-Mocana SSH" ||
    egrep( pattern:"^SSH-2\.0-Mocana SSH [0-9.]+$", string:banner ) )
  exit( 0 );

if( egrep( pattern:"^SSH-1\.99-OpenSSH_[0-9.p]+$", string:banner ) ||
    egrep( pattern:"^SSH-2\.0-OpenSSH_[0-9.p]+-FIPS_hpn[0-9v]+$", string:banner ) || # SSH-2.0-OpenSSH_6.1-FIPS_hpn13v11
    egrep( pattern:"^SSH-2\.0-OpenSSH_[0-9.p]+(\-FIPS\(capable\))?$", string:banner ) ||
    banner == "SSH-2.0-OpenSSH" ||
    banner == "SSH-2.0-OpenSSH_" )
  exit( 0 );

# Covered in gb_mikrotik_router_routeros_ssh_detect.nasl
if( banner == "SSH-2.0-ROSSSH" )
  exit( 0 );

# Probably Mina SSHD, cross-platform.
# e.g.:
# SSH-2.0-SSHD-CORE-0.13.1-SNAPSHOT
# SSH-2.0-SSHD
# SSH-2.0-SSHD-CORE-0.4.0
# SSH-2.0-SSHD-CORE-0.14.0
# SSH-2.0-SSHD-UNKNOWN
# SSH-2.0-SSHD-SERVER
if( egrep( pattern:"^SSH-2\.0-SSHD(-(UNKNOWN|SERVER|CORE)(-[0-9.]+)?(-SNAPSHOT)?)?$", string:banner ) )
  exit( 0 );

# Seen this on FreeBSD 11.3 but there might be others using the same so exclude it at least for now
#
# SSH-2.0-OpenSSH_8.0 Unknown
if( egrep( pattern:"^SSH-2.0-OpenSSH_[0-9.]+ Unknown$", string:banner ) )
  exit( 0 );

# pkixssh, cross-platform.
# e.g.
# SSH-2.0-OpenSSH_7.6 PKIX[11.0]
# SSH-2.0-OpenSSH_6.6 PKIX
# SSH-2.0-X PKIX[12.1]
if( egrep( pattern:"^SSH-2.0-[^ ]+ PKIX($|\[)", string:banner ) )
  exit( 0 );

# JSCAPE MFT Server, implemented in Java and cross-platform.
# e.g. SSH-2.0-JSCAPE
if( egrep( pattern:"^SSH-2\.0-JSCAPE$", string:banner ) )
  exit( 0 );

# Cross-platform, e.g.:
# SSH-2.0-GoAnywhere7.4.1
# SSH-2.0-GoAnywhere6.1.7
# SSH-2.0-GoAnywhere
if( egrep( pattern:"^SSH-2\.0-GoAnywhere", string:banner, icase:FALSE ) )
  exit( 0 );

# Cross-platform, e.g.:
# SSH-2.0-CrushFTPSSHD_5
# SSH-2.0-CrushFTPSSHD
if( egrep( pattern:"^SSH-2\.0-CrushFTPSSHD", string:banner, icase:FALSE ) )
  exit( 0 );

# Cross-platform, e.g.:
# SSH-2.0-Erlang/4.10.7
# SSH-2.0-Erlang/5.1.4.7
#
# nb: As the version might include some OS specific banner / pattern only the ones which have
# numbers are excluded here.
if( egrep( pattern:"^SSH-[0-9.]+-Erlang(/[0-9.]+)?$", string:banner, icase:FALSE ) )
  exit( 0 );

#For banners see e.g. https://github.com/BetterCrypto/Applied-Crypto-Hardening/blob/master/unsorted/ssh/ssh_version_strings.txt

# Order matters, as some banners can include several keywords.
# Ubuntu pattern for new releases last checked on 11/2017 (up to 17.10, LTS releases: 12.04 up to 12.04.5, 14.04 up to 14.04.5, 16.04 up to 16.04.3)
if( "ubuntu" >< tolower( banner ) )
{
  if( "SSH-2.0-OpenSSH_3.8.1p1 Debian 1:3.8.1p1-11ubuntu3" >< banner )
  {
    os_register_and_report( os:"Ubuntu", version:"4.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "SSH-2.0-OpenSSH_3.9p1 Debian-1ubuntu2" >< banner )
  {
    os_register_and_report( os:"Ubuntu", version:"5.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "SSH-2.0-OpenSSH_4.1p1 Debian-7ubuntu4" >< banner )
  {
    os_register_and_report( os:"Ubuntu", version:"5.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "SSH-2.0-OpenSSH_4.2p1 Debian-7ubuntu3" >< banner )
  {
    os_register_and_report( os:"Ubuntu", version:"6.06", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "SSH-2.0-OpenSSH_4.3p2 Debian-5ubuntu1" >< banner )
  {
    os_register_and_report( os:"Ubuntu", version:"6.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "SSH-2.0-OpenSSH_4.3p2 Debian-8ubuntu1" >< banner )
  {
    os_register_and_report( os:"Ubuntu", version:"7.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "SSH-2.0-OpenSSH_4.6p1 Debian-5ubuntu0" >< banner )
  {
    os_register_and_report( os:"Ubuntu", version:"7.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "SSH-2.0-OpenSSH_4.7p1 Debian-8ubuntu1" >< banner )
  {
    os_register_and_report( os:"Ubuntu", version:"8.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "SSH-2.0-OpenSSH_5.1p1 Debian-3ubuntu1" >< banner )
  {
    os_register_and_report( os:"Ubuntu", version:"8.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "SSH-2.0-OpenSSH_5.1p1 Debian-5ubuntu1" >< banner )
  {
    os_register_and_report( os:"Ubuntu", version:"9.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "SSH-2.0-OpenSSH_5.1p1 Debian-6ubuntu2" >< banner )
  {
    os_register_and_report( os:"Ubuntu", version:"9.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "SSH-2.0-OpenSSH_5.3p1 Debian-3ubuntu3" >< banner || "SSH-2.0-OpenSSH_5.3p1 Debian-3ubuntu4" >< banner ||
      "SSH-2.0-OpenSSH_5.3p1 Debian-3ubuntu5" >< banner || "SSH-2.0-OpenSSH_5.3p1 Debian-3ubuntu6" >< banner ||
      "SSH-2.0-OpenSSH_5.3p1 Debian-3ubuntu7" >< banner )
  {
    os_register_and_report( os:"Ubuntu", version:"10.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "SSH-2.0-OpenSSH_5.5p1 Debian-4ubuntu3" >< banner || "SSH-2.0-OpenSSH_5.5p1 Debian-4ubuntu4" >< banner || "SSH-2.0-OpenSSH_5.5p1 Debian-4ubuntu5" >< banner)
  {
    os_register_and_report( os:"Ubuntu", version:"10.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "SSH-2.0-OpenSSH_5.8p1 Debian-1ubuntu3" >< banner )
  {
    os_register_and_report( os:"Ubuntu", version:"11.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "SSH-2.0-OpenSSH_5.8p1 Debian-7ubuntu1" >< banner )
  {
    os_register_and_report( os:"Ubuntu", version:"11.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "SSH-2.0-OpenSSH_5.9p1 Debian-5ubuntu" >< banner )
  {
    os_register_and_report( os:"Ubuntu", version:"12.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "SSH-2.0-OpenSSH_6.0p1 Debian-3ubuntu" >< banner )
  {
    os_register_and_report( os:"Ubuntu", version:"12.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "SSH-2.0-OpenSSH_6.1p1 Debian-3ubuntu" >< banner )
  {
    os_register_and_report( os:"Ubuntu", version:"13.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "SSH-2.0-OpenSSH_6.2p2 Ubuntu-6" >< banner )
  {
    os_register_and_report( os:"Ubuntu", version:"13.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "SSH-2.0-OpenSSH_6.6p1 Ubuntu-2" >< banner || "SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2" >< banner )
  {
    os_register_and_report( os:"Ubuntu", version:"14.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-8" >< banner )
  {
    os_register_and_report( os:"Ubuntu", version:"14.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "SSH-2.0-OpenSSH_6.7p1 Ubuntu-5ubuntu1" >< banner )
  {
    os_register_and_report( os:"Ubuntu", version:"15.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "SSH-2.0-OpenSSH_6.9p1 Ubuntu-2" >< banner )
  {
    os_register_and_report( os:"Ubuntu", version:"15.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "SSH-2.0-OpenSSH_7.2p2 Ubuntu-4" >< banner )
  {
    os_register_and_report( os:"Ubuntu", version:"16.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "SSH-2.0-OpenSSH_7.3p1 Ubuntu-1" >< banner )
  {
    os_register_and_report( os:"Ubuntu", version:"16.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "SSH-2.0-OpenSSH_7.4p1 Ubuntu-10" >< banner )
  {
    os_register_and_report( os:"Ubuntu", version:"17.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "SSH-2.0-OpenSSH_7.5p1 Ubuntu-10" >< banner )
  {
    os_register_and_report( os:"Ubuntu", version:"17.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "SSH-2.0-OpenSSH_7.6p1 Ubuntu-4" >< banner )
  {
    os_register_and_report( os:"Ubuntu", version:"18.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "SSH-2.0-OpenSSH_7.7p1 Ubuntu-4" >< banner )
  {
    os_register_and_report( os:"Ubuntu", version:"18.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "SSH-2.0-OpenSSH_7.9p1 Ubuntu-10" >< banner )
  {
    os_register_and_report( os:"Ubuntu", version:"19.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "SSH-2.0-OpenSSH_8.0p1 Ubuntu-6" >< banner )
  {
    os_register_and_report( os:"Ubuntu", version:"19.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4" >< banner )
  {
    os_register_and_report( os:"Ubuntu", version:"20.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "SSH-2.0-OpenSSH_8.3p1 Ubuntu-1" >< banner )
  {
    os_register_and_report( os:"Ubuntu", version:"20.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "SSH-2.0-OpenSSH_8.4p1 Ubuntu-5ubuntu1" >< banner )
  {
    os_register_and_report( os:"Ubuntu", version:"21.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "SSH-2.0-OpenSSH_8.4p1 Ubuntu-6ubuntu2" >< banner )
  {
    os_register_and_report( os:"Ubuntu", version:"21.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3" >< banner )
  {
    os_register_and_report( os:"Ubuntu", version:"22.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "SSH-2.0-OpenSSH_9.0p1 Ubuntu-1ubuntu7" >< banner )
  {
    os_register_and_report( os:"Ubuntu", version:"22.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "SSH-2.0-OpenSSH_9.0p1 Ubuntu-1ubuntu8" >< banner )
  {
    os_register_and_report( os:"Ubuntu", version:"23.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "SSH-2.0-OpenSSH_9.3p1 Ubuntu-1ubuntu3.3" >< banner )
  {
    os_register_and_report( os:"Ubuntu", version:"23.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13" >< banner )
  {
    os_register_and_report( os:"Ubuntu", version:"24.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }
  # We don't know the OS version
  os_register_and_report( os:"Ubuntu", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

else if( "Debian" >< banner || "Raspbian" >< banner )
{
  # Special case on Ubuntu 7.10
  if( "SSH-2.0-OpenSSH_4.6p1 Debian-5build1" >< banner )
  {
    os_register_and_report( os:"Ubuntu", version:"7.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  # Another special case on Ubuntu 13.04
  if( "SSH-2.0-OpenSSH_6.1p1 Debian-4" >< banner )
  {
    os_register_and_report( os:"Ubuntu", version:"13.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  # SSH-2.0-OpenSSH_3.4p1 Debian 1:3.4p1-1.woody.3
  if( "SSH-2.0-OpenSSH_3.4p1 Debian 1" >< banner )
  {
    os_register_and_report( os:"Debian GNU/Linux", version:"3.0", cpe:"cpe:/o:debian:debian_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  # SSH-2.0-OpenSSH_3.8.1p1 Debian-8.sarge.6
  if( "SSH-2.0-OpenSSH_3.8.1p1 Debian-8" >< banner )
  {
    os_register_and_report( os:"Debian GNU/Linux", version:"3.1", cpe:"cpe:/o:debian:debian_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  # SSH-2.0-OpenSSH_4.3p2 Debian-9etch3
  if( "SSH-2.0-OpenSSH_4.3p2 Debian-9" >< banner )
  {
    os_register_and_report( os:"Debian GNU/Linux", version:"4.0", cpe:"cpe:/o:debian:debian_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  # SSH-2.0-OpenSSH_5.1p1 Debian-5
  if( "SSH-2.0-OpenSSH_5.1p1 Debian" >< banner )
  {
    os_register_and_report( os:"Debian GNU/Linux", version:"5.0", cpe:"cpe:/o:debian:debian_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  # SSH-2.0-OpenSSH_5.5p1 Debian-6+squeeze8
  if( "SSH-2.0-OpenSSH_5.5p1 Debian-6" >< banner )
  {
    os_register_and_report( os:"Debian GNU/Linux", version:"6.0", cpe:"cpe:/o:debian:debian_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  # SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u7
  # nb: Starting with Wheezy (7.x) we have minor releases within the version so we don't use an exact version like 7.0 as we can't differ between the OS in the banner here
  if( "SSH-2.0-OpenSSH_6.0p1 Debian-4" >< banner || ( "~bpo7" >< banner && "SSH-2.0-OpenSSH_" >< banner ) )
  {
    os_register_and_report( os:"Debian GNU/Linux", version:"7", cpe:"cpe:/o:debian:debian_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  # SSH-2.0-OpenSSH_6.7p1 Debian-5+deb8u8
  if( "SSH-2.0-OpenSSH_6.7p1 Debian-5" >< banner || "SSH-2.0-OpenSSH_6.7p1 Raspbian-5" >< banner || ( "~bpo8" >< banner && "SSH-2.0-OpenSSH_" >< banner ) )
  {
    os_register_and_report( os:"Debian GNU/Linux", version:"8", cpe:"cpe:/o:debian:debian_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  # SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u7
  if( "SSH-2.0-OpenSSH_7.4p1 Debian-10" >< banner || "SSH-2.0-OpenSSH_7.4p1 Raspbian-10" >< banner || ( "~bpo9" >< banner && "SSH-2.0-OpenSSH_" >< banner ) )
  {
    os_register_and_report( os:"Debian GNU/Linux", version:"9", cpe:"cpe:/o:debian:debian_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  # SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u2
  if( "SSH-2.0-OpenSSH_7.9p1 Debian-10" >< banner || "SSH-2.0-OpenSSH_7.9p1 Raspbian-10" >< banner || ( "~bpo10" >< banner && "SSH-2.0-OpenSSH_" >< banner ) )
  {
    os_register_and_report( os:"Debian GNU/Linux", version:"10", cpe:"cpe:/o:debian:debian_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  # SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u1
  if( "SSH-2.0-OpenSSH_8.4p1 Debian-5" >< banner || "SSH-2.0-OpenSSH_8.4p1 Raspbian-5" >< banner || ( "~bpo11" >< banner && "SSH-2.0-OpenSSH_" >< banner ) )
  {
    os_register_and_report( os:"Debian GNU/Linux", version:"11", cpe:"cpe:/o:debian:debian_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  # SSH-2.0-OpenSSH_9.2p1 Debian-2 other pattern may show up in the future
  if( "SSH-2.0-OpenSSH_9.2p1 Debian-2" >< banner || ( "~bpo12" >< banner && "SSH-2.0-OpenSSH_" >< banner ) )
  {
    os_register_and_report( os:"Debian GNU/Linux", version:"12", cpe:"cpe:/o:debian:debian_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  # We don't know the OS version
  os_register_and_report( os:"Debian GNU/Linux", cpe:"cpe:/o:debian:debian_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# nb:
# - "VersionAddendum" in https://www.freebsd.org/cgi/man.cgi?query=sshd_config
# - Additional sources: https://github.com/richlamdev/ssh-default-banners/blob/master/freebsd_tsv.txt
# - Some FreeBSD versions (e.g. 12.0 and 12.1) are sharing the same banner. In this case the highest
#   version was chosen and an comment added in the related code below.
else if( "FreeBSD" >< banner )
{
  if( "SSH-1.99-OpenSSH_2.3.0 green@FreeBSD.org 20010321" >< banner )
  {
    os_register_and_report( os:"FreeBSD", version:"4.3", cpe:"cpe:/o:freebsd:freebsd", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "SSH-1.99-OpenSSH_2.3.0 FreeBSD localisations 20010713" >< banner )
  {
    os_register_and_report( os:"FreeBSD", version:"4.4", cpe:"cpe:/o:freebsd:freebsd", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "SSH-1.99-OpenSSH_2.9 FreeBSD localisations 20011202" >< banner )
  {
    os_register_and_report( os:"FreeBSD", version:"4.5", cpe:"cpe:/o:freebsd:freebsd", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "SSH-1.99-OpenSSH_2.9 FreeBSD localisations 20020307" >< banner )
  {
    os_register_and_report( os:"FreeBSD", version:"4.6", cpe:"cpe:/o:freebsd:freebsd", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "SSH-1.99-OpenSSH_3.4p1 FreeBSD-20020702" >< banner )
  {
    os_register_and_report( os:"FreeBSD", version:"4.7", cpe:"cpe:/o:freebsd:freebsd", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "SSH-1.99-OpenSSH_3.5p1 FreeBSD-20030201" >< banner )
  {
    os_register_and_report( os:"FreeBSD", version:"4.8", cpe:"cpe:/o:freebsd:freebsd", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  # nb: 4.9, 4.10 and 4.11 are sharing the same SSH-1.99-OpenSSH_3.5p1 FreeBSD-20030924 banner
  if( "SSH-1.99-OpenSSH_3.5p1 FreeBSD-20030924" >< banner || "SSH-1.99-OpenSSH_3.5p1 FreeBSD-20060930" >< banner )
  {
    os_register_and_report( os:"FreeBSD", version:"4.11", cpe:"cpe:/o:freebsd:freebsd", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "SSH-1.99-OpenSSH_3.5p1 FreeBSD-20021029" >< banner )
  {
    os_register_and_report( os:"FreeBSD", version:"5.0", cpe:"cpe:/o:freebsd:freebsd", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "SSH-1.99-OpenSSH_3.6.1p1 FreeBSD-20030423" >< banner )
  {
    os_register_and_report( os:"FreeBSD", version:"5.1", cpe:"cpe:/o:freebsd:freebsd", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "SSH-1.99-OpenSSH_3.6.1p1 FreeBSD-20030924" >< banner )
  {
    os_register_and_report( os:"FreeBSD", version:"5.2", cpe:"cpe:/o:freebsd:freebsd", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  # nb: 5.3 and 5.4 are sharing the same banner
  if( "SSH-2.0-OpenSSH_3.8.1p1 FreeBSD-20040419" >< banner )
  {
    os_register_and_report( os:"FreeBSD", version:"5.4", cpe:"cpe:/o:freebsd:freebsd", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "SSH-2.0-OpenSSH_3.8.1p1 FreeBSD-20060123" >< banner )
  {
    os_register_and_report( os:"FreeBSD", version:"5.5", cpe:"cpe:/o:freebsd:freebsd", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  # nb: 6.0 and 6.1 are sharing the same banner
  if( "SSH-2.0-OpenSSH_4.2p1 FreeBSD-20050903" >< banner )
  {
    os_register_and_report( os:"FreeBSD", version:"6.1", cpe:"cpe:/o:freebsd:freebsd", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "SSH-2.0-OpenSSH_4.5p1 FreeBSD-20061110" >< banner )
  {
    os_register_and_report( os:"FreeBSD", version:"7.0", cpe:"cpe:/o:freebsd:freebsd", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  # nb: 7.1, 7.2, 7.3 and 7.4 are sharing the same banner
  if( "SSH-2.0-OpenSSH_5.1p1 FreeBSD-20080901" >< banner )
  {
    os_register_and_report( os:"FreeBSD", version:"7.4", cpe:"cpe:/o:freebsd:freebsd", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "SSH-2.0-OpenSSH_5.2p1 FreeBSD-20090522" >< banner )
  {
    os_register_and_report( os:"FreeBSD", version:"8.0", cpe:"cpe:/o:freebsd:freebsd", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  # nb: 8.1 and 8.2 are sharing the same banner
  if( "SSH-2.0-OpenSSH_5.4p1 FreeBSD-20100308" >< banner )
  {
    os_register_and_report( os:"FreeBSD", version:"8.2", cpe:"cpe:/o:freebsd:freebsd", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "SSH-2.0-OpenSSH_5.4p1_hpn13v11 FreeBSD-20100308" >< banner )
  {
    os_register_and_report( os:"FreeBSD", version:"8.3", cpe:"cpe:/o:freebsd:freebsd", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "SSH-2.0-OpenSSH_6.1_hpn13v11 FreeBSD-20120901" >< banner )
  {
    os_register_and_report( os:"FreeBSD", version:"8.4", cpe:"cpe:/o:freebsd:freebsd", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  # nb: 9.0 and 9.1 are sharing the same banner
  if( "SSH-2.0-OpenSSH_5.8p2_hpn13v11 FreeBSD-20110503" >< banner )
  {
    os_register_and_report( os:"FreeBSD", version:"9.1", cpe:"cpe:/o:freebsd:freebsd", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "SSH-2.0-OpenSSH_6.2_hpn13v11 FreeBSD-20130515" >< banner )
  {
    os_register_and_report( os:"FreeBSD", version:"9.2", cpe:"cpe:/o:freebsd:freebsd", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "SSH-2.0-OpenSSH_6.4_hpn13v11 FreeBSD-20131111" >< banner )
  {
    os_register_and_report( os:"FreeBSD", version:"10.0", cpe:"cpe:/o:freebsd:freebsd", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  # nb: 9.3, 10.1 and 10.2 are sharing the same banner
  if( "SSH-2.0-OpenSSH_6.6.1_hpn13v11 FreeBSD-20140420" >< banner )
  {
    os_register_and_report( os:"FreeBSD", version:"10.2", cpe:"cpe:/o:freebsd:freebsd", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "SSH-2.0-OpenSSH_7.3 FreeBSD-20170902" >< banner )
  {
    os_register_and_report( os:"FreeBSD", version:"10.4", cpe:"cpe:/o:freebsd:freebsd", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  # nb: 10.3 and 11.0 are sharing the same banner
  if( "SSH-2.0-OpenSSH_7.2 FreeBSD-20160310" >< banner )
  {
    os_register_and_report( os:"FreeBSD", version:"11.0", cpe:"cpe:/o:freebsd:freebsd", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "SSH-2.0-OpenSSH_7.2 FreeBSD-20161230" >< banner )
  {
    os_register_and_report( os:"FreeBSD", version:"11.1", cpe:"cpe:/o:freebsd:freebsd", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  # nb: 11.2, 11.3 and 11.4 are sharing the same banner
  if( "SSH-2.0-OpenSSH_7.5 FreeBSD-20170903" >< banner )
  {
    os_register_and_report( os:"FreeBSD", version:"11.4", cpe:"cpe:/o:freebsd:freebsd", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  # nb: 12.0 and 12.1 are sharing the same banner
  if( "SSH-2.0-OpenSSH_7.8 FreeBSD-20180909" >< banner )
  {
    os_register_and_report( os:"FreeBSD", version:"12.1", cpe:"cpe:/o:freebsd:freebsd", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "SSH-2.0-OpenSSH_7.9 FreeBSD-20200214" >< banner )
  {
    os_register_and_report( os:"FreeBSD", version:"13.0", cpe:"cpe:/o:freebsd:freebsd", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "SSH-2.0-OpenSSH_8.8 FreeBSD-20211221" >< banner )
  {
    os_register_and_report( os:"FreeBSD", version:"13.1", cpe:"cpe:/o:freebsd:freebsd", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  # We don't know the OS version
  os_register_and_report( os:"FreeBSD", cpe:"cpe:/o:freebsd:freebsd", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

else if( "OpenBSD" >< banner )
{
  # We don't know the OS version
  os_register_and_report( os:"OpenBSD", cpe:"cpe:/o:openbsd:openbsd", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

else if( "NetBSD" >< banner )
{
  # We don't know the OS version
  os_register_and_report( os:"NetBSD", cpe:"cpe:/o:netbsd:netbsd", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# SSH-2.0-CISCO_WLC
# nb: More detailed OS Detection covered in gb_cisco_wlc_consolidation.nasl
else if( "CISCO_WLC" >< banner )
{
  os_register_and_report( os:"Cisco Wireless LAN Controller Firmware", cpe:"cpe:/o:cisco:wireless_lan_controller", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# e.g.:
# SSH-1.99-Cisco-1.25
# SSH-2.0-Cisco-1.25
# SSH-1.99-Cisco-2.0
# SSH-2.0-Cisco-2.0
else if( banner =~ "^SSH-[0-9.]+-Cisco-[0-9.]+" )
{
  os_register_and_report( os:"Cisco IOS", cpe:"cpe:/o:cisco:ios", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

else if( eregmatch( string:banner, pattern:"(cisco|FIPS User Access Verification)", icase:TRUE ) || "Cisco Systems, Inc. All rights Reserved" >< login_banner )
{
  os_register_and_report( os:"Cisco", cpe:"cpe:/o:cisco", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

else if( banner =~ "SSH-[0-9.]+-Sun_SSH" )
{
  os_register_and_report( os:"SunOS", cpe:"cpe:/o:sun:sunos", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

else if( "SSH-2.0-NetScreen" >< banner )
{
  os_register_and_report( os:"NetScreen ScreenOS", cpe:"cpe:/o:juniper:netscreen_screenos", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

else if( eregmatch( string:banner, pattern:"SSH-2.0-xxxxxxx|FortiSSH" ) )
{
  os_register_and_report( os:"FortiOS", cpe:"cpe:/o:fortinet:fortios", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

else if( "OpenVMS" >< banner )
{
  os_register_and_report( os:"OpenVMS", cpe:"cpe:/o:hp:openvms", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

else if( "SSH-2.0-MS_" >< banner )
{
  os_register_and_report( os:"Microsoft Windows", cpe:"cpe:/o:microsoft:windows_10:-:-:iot", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
  exit( 0 );
}

# SSH-2.0-WeOnlyDo 2.4.3
# SSH-2.0-WeOnlyDo-wodFTPD 3.3.0.424
# Both from http://www.freesshd.com running on Windows only
else if( "SSH-2.0-WeOnlyDo" >< banner )
{
  os_register_and_report( os:"Microsoft Windows", cpe:"cpe:/o:microsoft:windows", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
  exit( 0 );
}

else if( "SSH-2.0-mpSSH_" >< banner )
{
  os_register_and_report( os:"HP iLO", cpe:"cpe:/o:hp:integrated_lights-out", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

else if( "SSH-2.0-Data ONTAP SSH" >< banner )
{
  os_register_and_report( os:"NetApp Data ONTAP", cpe:"cpe:/o:netapp:data_ontap", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# Embedded Linux
else if( "SSH-2.0-moxa_" >< banner )
{
  os_register_and_report( os:"Linux/Unix", cpe:"cpe:/o:linux:kernel", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# SolarWinds Network Configuration Manager (NCM) running on Windows only.
else if( "Network ConfigManager SCP Server" >< banner )
{
  os_register_and_report( os:"Microsoft Windows", cpe:"cpe:/o:microsoft:windows", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
  exit( 0 );
}

# SSH-2.0-OpenSSH_for_Windows_7.9
else if( "OpenSSH_for_Windows" >< banner )
{
  os_register_and_report( os:"Microsoft Windows", cpe:"cpe:/o:microsoft:windows", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
  exit( 0 );
}

# nb: More detailed OS Detection covered in gb_netapp_data_ontap_consolidation.nasl
else if( egrep( pattern:"SSH.+Data ONTAP SSH", string:banner ) )
{
  os_register_and_report( os:"NetApp Data ONTAP", cpe:"cpe:/o:netapp:data_ontap", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# nb: More detailed OS Detection covered in gsf/gb_zyxel_usg_consolidation.nasl
else if( egrep( pattern:"SSH.+-Zyxel SSH server", string:banner ) )
{
  os_register_and_report( os:"Zyxel USG Firmware", cpe:"cpe:/o:zyxel:usg_firmware", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# SSH-2.0-WS_FTP-SSH_8.7.1.109
# nb: More detailed OS Detection covered in gsf/gb_progress_ws_ftp_server_ssh_detect.nasl
else if( egrep( pattern:"SSH.+-WS_FTP-SSH", string:banner ) )
{
  os_register_and_report( os:"Microsoft Windows", cpe:"cpe:/o:microsoft:windows", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
  exit( 0 );
}

# Nexus 5000 Switch
# Nexus 3000 Switch
else if( egrep( pattern:"Nexus [0-9]+ Switch", string:login_banner ) )
{
  os_register_and_report( os:"Cisco NX-OS", cpe:"cpe:/o:cisco:nx-os", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# SSH-2.0-ArrayOS
else if( egrep( pattern:"SSH-.+ArrayOS", string:banner ) )
{
  os_register_and_report( os:"Array ArrayOS", cpe:"cpe:/o:arraynetworks:arrayos", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# SSH-2.0-Greenbone_7.4p2gb Greenbone OS 6.0
#
# Older releases of GOS had also a pre-login banner like e.g.:
#
# Welcome to Greenbone OS 1.6
#
# nb: More detailed OS Detection covered in gb_greenbone_os_ssh_detect.nasl
else if( egrep( pattern:"SSH.+Greenbone OS", string:banner ) || "Welcome to Greenbone OS" >< login_banner )
{
  os_register_and_report( os:"Greenbone OS (GOS)", cpe:"cpe:/o:greenbone:greenbone_os", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# SSH-2.0-HUAWEI-1.5
else if( banner == "SSH-2.0--" || "SSH-2.0-HUAWEI-" >< banner || banner == "SSH-1.99--" ) {
  os_register_and_report( os:"Huawei Unknown Model Versatile Routing Platform (VRP) network device Firmware", cpe:"cpe:/o:huawei:vrp_firmware", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# Seems to run on embedded Linux/Unix on Devices like:
# 3Com WX2200 or WX4400
# Juniper Trapeze
# e.g.
# SSH-2.0-NOS-SSH_2.0
else if( "SSH-2.0-NOS-SSH" >< banner )
{
  os_register_and_report( os:"Linux/Unix", cpe:"cpe:/o:linux:kernel", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# SSH-2.0-1.09 FlowSsh: WinSSHD 5.26
# SSH-2.0-1.82 sshlib: WinSSHD 4.28
# SSH-2.0-5.23 FlowSsh: Bitvise SSH Server (WinSSHD) 6.04
# SSH-2.0-5.17 FlowSsh: Bitvise SSH Server (WinSSHD) 5.60: free only for personal non-commercial use
# SSH-2.0-8.49 FlowSsh: Bitvise SSH Server (WinSSHD) 8.49
# SSH-2.0-9.32 FlowSsh: Bitvise SSH Server (WinSSHD) 9.32: free only for personal non-commercial use
# SSH-2.0-9.99 FlowSsh: Bitvise SSH Server (WinSSHD)
else if( "WinSSHD" >< banner )
{
  os_register_and_report( os:"Microsoft Windows", cpe:"cpe:/o:microsoft:windows", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
  exit( 0 );
}

# nb: Currently registering with "unixoide" KB key but there are some reports that a few devices
# which might run on Windows CE. If it is ever required we also might register this twice or similar
# but for now it should be fine to use "unixoide"...
else if( "SSH-2.0-CrestronSSH" >< banner )
{
  os_register_and_report( os:"Crestron Device Firmware", cpe:"cpe:/o:crestron:device_firmware", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# SSH-2.0-OpenSSH_4.3p2, OpenSSL 0.9.8e-fips-rhel5 01 Jul 2008
if( banner =~ "OpenSSL.+-rhel" ) {
  version = eregmatch( pattern:"OpenSSL.+-rhel([0-9]+)", string:banner, icase:FALSE );
  if( ! isnull( version[1] ) )
    os_register_and_report( os:"Red Hat Enterprise Linux", version:version[1], cpe:"cpe:/o:redhat:enterprise_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  else
    os_register_and_report( os:"Red Hat Enterprise Linux", cpe:"cpe:/o:redhat:enterprise_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );

  exit( 0 );
}

# SSH-2.0-MOVEit Transfer SFTP
else if( banner =~ "SSH-.+\-MOVEit Transfer SFTP" )
{
  os_register_and_report( os:"Microsoft Windows", cpe:"cpe:/o:microsoft:windows", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
  exit( 0 );
}

# SSH-2.0-1.82_sshlib GlobalSCAPE
# SSH-2.0-7.9.0.0_openssh Globalscape
else if( banner =~ "SSH-.+ Globalscape" )
{
  os_register_and_report( os:"Microsoft Windows", cpe:"cpe:/o:microsoft:windows", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
  exit( 0 );
}

# SSH-2.0-IPSSH-6.9.0 Easergy-P5
else if( banner =~ "SSH-.+ Easergy-P[0-9]" )
{
  os_register_and_report( os:"Schneider Electric PowerLogic Protection Firmware", cpe:"cpe:/o:schneider-electric:easergy_protection_firmware", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# SSH-2.0-AudioCodes
else if( banner =~ "SSH-.+AudioCodes" )
{
  os_register_and_report( os:"AudioCodes Mediant Firmware", cpe:"cpe:/o:audiocodes:mediant_firmware", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

os_register_unknown_banner( banner:banner, banner_type_name:BANNER_TYPE, banner_type_short:"ssh_banner", port:port );

exit( 0 );
