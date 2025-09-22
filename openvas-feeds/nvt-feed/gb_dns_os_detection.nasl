# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108014");
  script_version("2025-07-30T05:45:23+0000");
  script_tag(name:"last_modification", value:"2025-07-30 05:45:23 +0000 (Wed, 30 Jul 2025)");
  script_tag(name:"creation_date", value:"2016-11-03 14:13:48 +0100 (Thu, 03 Nov 2016)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Operating System (OS) Detection (DNS)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("dns_server_tcp.nasl", "dns_server.nasl");
  script_mandatory_keys("dns/server/detected");

  script_tag(name:"summary", value:"DNS banner based Operating System (OS) detection.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("os_func.inc");

SCRIPT_DESC = "Operating System (OS) Detection (DNS)";
BANNER_TYPE = "DNS server banner";

foreach proto( make_list( "udp", "tcp" ) ) {

  banners = get_kb_list( "DNS/" + proto + "/version_request/*" );
  if( ! banners )
    continue;

  foreach key( keys( banners ) ) {

    kb_key = "DNS/" + proto + "/version_request/";
    port   = int( key - kb_key );
    banner = banners[key];

    if( "Microsoft" >< banner || "Windows" >< banner ) {
      if( "Windows 2008 DNS Server Ready" >< banner ) {
        os_register_and_report( os:"Microsoft Windows 2008 Server", cpe:"cpe:/o:microsoft:windows_server_2008", banner_type:BANNER_TYPE, port:port, proto:proto, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
      } else {
        os_register_and_report( os:"Microsoft Windows", cpe:"cpe:/o:microsoft:windows", banner_type:BANNER_TYPE, port:port, proto:proto, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
      }
      continue;
    }

    if( "FreeBSD" >< banner ) {
      os_register_and_report( os:"FreeBSD", cpe:"cpe:/o:freebsd:freebsd", banner_type:BANNER_TYPE, port:port, proto:proto, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      continue;
    }

    if( "SunOS DNS Server" >< banner ) {
      os_register_and_report( os:"SunOS", cpe:"cpe:/o:sun:sunos", banner_type:BANNER_TYPE, port:port, proto:proto, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      continue;
    }

    if( "Gentoo Gnu/Linux" >< banner ) {
      os_register_and_report( os:"Gentoo", cpe:"cpe:/o:gentoo:linux", banner_type:BANNER_TYPE, port:port, proto:proto, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      continue;
    }

    # 9.11.5-P4-5.1ubuntu2.1-Ubuntu
    if( banner =~ "ubuntu" ) {
      if( "9.11.5-P4-5.1ubuntu" >< banner )
        os_register_and_report( os:"Ubuntu", version:"19.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, proto:proto, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      else
        os_register_and_report( os:"Ubuntu", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, proto:proto, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      continue;
    }

    # PowerDNS Authoritative Server 3.4.11 (jenkins@autotest.powerdns.com built 20170116223245 mockbuild@buildhw-05.phx2.fedoraproject.org)
    if( "for Fedora Linux" >< banner || ( ( "PowerDNS" >< banner || "jenkins@autotest.powerdns.com" >< banner ) && ".fedoraproject.org" >< banner ) ) {
      os_register_and_report( os:"Fedora Linux", cpe:"cpe:/o:fedoraproject:fedora", banner_type:BANNER_TYPE, port:port, proto:proto, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      continue;
    }

    if( "-SuSE" >< banner ) {
      os_register_and_report( os:"SUSE Linux", cpe:"cpe:/o:novell:suse_linux", banner_type:BANNER_TYPE, port:port, proto:proto, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      continue;
    }

    if( "-RedHat" >< banner && ".fc" >< banner ) {
      version = eregmatch( pattern:"\.fc([0-9]+)", string:banner );
      if( ! isnull( version[1] ) ) {
        os_register_and_report( os:"Fedora Linux", version:version[1], cpe:"cpe:/o:fedoraproject:fedora", banner_type:BANNER_TYPE, port:port, proto:proto, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else {
        os_register_and_report( os:"Fedora Linux", cpe:"cpe:/o:fedoraproject:fedora", banner_type:BANNER_TYPE, port:port, proto:proto, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      }
      continue;
    }

    # 9.9.4-RedHat-9.9.4-50.1.h2
    if( banner =~ "-RedHat.+\.h" ) {
      version = eregmatch( pattern:"[0-9.-]+\.h([1-9])", string:banner );
      if( ! isnull( version[1] ) ) {
        os_register_and_report( os:"EulerOS", version:version[1], cpe:"cpe:/o:huawei:euleros", banner_type:BANNER_TYPE, port:port, proto:proto, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else {
        os_register_and_report( os:"EulerOS", cpe:"cpe:/o:huawei:euleros", banner_type:BANNER_TYPE, port:port, proto:proto, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      }
      continue;
    }

    if( "-RedHat" >< banner ) {
      version = eregmatch( pattern:"\.el([0-9]+)", string:banner );
      if( ! isnull( version[1] ) ) {
        os_register_and_report( os:"Redhat Linux", version:version[1], cpe:"cpe:/o:redhat:linux", banner_type:BANNER_TYPE, port:port, proto:proto, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else {
        os_register_and_report( os:"Redhat Linux", cpe:"cpe:/o:redhat:linux", banner_type:BANNER_TYPE, port:port, proto:proto, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      }
      continue;
    }

    # PowerDNS" "Authoritative" "Server" "3.4.11" "(jenkins@autotest.powerdns.com" "built" "20171130121213" "root@rpmb-64-centos-65)
    # PowerDNS" "Authoritative" "Server" "3.4.10" "(jenkins@autotest.powerdns.com" "built" "20170306160718" "root@rpmbuild-64-centos-7.dev.cpanel.net)
    if( ( "PowerDNS" >< banner || "jenkins@autotest.powerdns.com" >< banner ) && "-centos-" >< banner ) {
      if( "-centos-7" >< banner ) {
        os_register_and_report( os:"CentOS", version:"7", cpe:"cpe:/o:centos:centos", banner_type:BANNER_TYPE, port:port, proto:proto, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "-centos-65" >< banner ) {
        os_register_and_report( os:"CentOS", version:"6.5", cpe:"cpe:/o:centos:centos", banner_type:BANNER_TYPE, port:port, proto:proto, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else {
        os_register_and_report( os:"CentOS", cpe:"cpe:/o:centos:centos", banner_type:BANNER_TYPE, port:port, proto:proto, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      }
      continue;
    }

    # PowerDNS Authoritative Server 3.4.1 (jenkins@autotest.powerdns.com built 20171202211242 root@x86-ubc-01.debian.org)
    #
    # nb:
    # - Seems only Debian 8 and later included the OS info
    # - Order matters a little so that e.g. "~bpo11" in "9.18.16-1~deb12u1~bpo11+1-Debian" is
    #   detected before "~deb12" as we need to detect Debian 11 and not Debian 12 in this case.
    #
    # 9.9.5-9+deb8u6-Debian
    # 9.9.5-9+deb8u29-Debian
    # 9.11.2-P1-1~bpo9+1-Debian
    # 9.11.5-P4-5~bpo9+1-Debian
    # 9.11.5-P4-5.1+deb10u1-Debian
    # 9.18.16-1~deb12u1~bpo11+1-Debian
    # 9.18.12-1~bpo11+1-Debian
    # 9.16.44-Debian (this was bind9 package 1:9.16.44-1~deb11u1 and the banner didn't included the "-1")
    #
    # nb: On Debian 12/bookworn the versioning scheme changed to include the "-1" from the package:
    #
    # 9.18.16-1-Debian (for bind9 package 1:9.18.16-1~deb12u1)
    # 9.18.19-1-Debian (for bind9 package 1:9.18.19-1~deb12u1)
    # 9.18.24-1-Debian (for bind9 package 1:9.18.24-1)
    # 9.18.28-1~deb12u1-Debian (for bind9 package 1:9.18.28-1~deb12u1)
    # 9.18.28-1~deb12u2-Debian (for bind9 package 1:9.18.28-1~deb12u2)
    # 9.18.33-1~deb12u2-Debian (for bind9 package 1:9.18.33-1~deb12u2)
    #
    # also seen the following for Debian 12 (banner info might depend on some configuration or similar):
    #
    # 9.18.16-1~deb12u1-Debian
    # 9.18.19-1~deb12u1-Debian
    #
    # General info on the Debian packages can be found here:
    # - https://packages.debian.org/search?keywords=bind9
    # - https://packages.qa.debian.org/b/bind9.html ("News" section with entries like "in bookworm-security")
    #
    if( "-Debian" >< banner || ( "PowerDNS Authoritative Server" >< banner && "debian.org)" >< banner ) ) {
      if( "~deb8" >< banner || "+deb8" >< banner ) {
        os_register_and_report( os:"Debian GNU/Linux", version:"8", cpe:"cpe:/o:debian:debian_linux", banner_type:BANNER_TYPE, port:port, proto:proto, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "9.10.3-P4-Debian" >< banner || "~deb9" >< banner || "+deb9" >< banner || "~bpo9" >< banner ) {
        os_register_and_report( os:"Debian GNU/Linux", version:"9", cpe:"cpe:/o:debian:debian_linux", banner_type:BANNER_TYPE, port:port, proto:proto, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "9.11.5-P4-5.1-Debian" >< banner || "~deb10" >< banner || "+deb10" >< banner || "~bpo10" >< banner ) {
        os_register_and_report( os:"Debian GNU/Linux", version:"10", cpe:"cpe:/o:debian:debian_linux", banner_type:BANNER_TYPE, port:port, proto:proto, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "9.16.33-Debian" >< banner || "9.16.27-Debian" >< banner || "9.16.37-Debian" >< banner || "9.16.42-Debian" >< banner || "9.16.44-Debian" >< banner || "9.16.48-Debian" >< banner || "~deb11" >< banner || "+deb11" >< banner || "~bpo11" >< banner ) {
        os_register_and_report( os:"Debian GNU/Linux", version:"11", cpe:"cpe:/o:debian:debian_linux", banner_type:BANNER_TYPE, port:port, proto:proto, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "9.18.16-1-Debian" >< banner || "9.18.19-1-Debian" >< banner || "9.18.24-1-Debian" >< banner || "~deb12" >< banner || "+deb12" >< banner || "~bpo12" >< banner ) {
        os_register_and_report( os:"Debian GNU/Linux", version:"12", cpe:"cpe:/o:debian:debian_linux", banner_type:BANNER_TYPE, port:port, proto:proto, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else {
        os_register_and_report( os:"Debian GNU/Linux", cpe:"cpe:/o:debian:debian_linux", banner_type:BANNER_TYPE, port:port, proto:proto, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      }
      continue;
    }

    # Those are only running on Unix-like OS variants
    # keep at the bottom so the pattern above are evaluated first.
    # dnsmasq-pi-hole-2.79
    # dnsmasq-2.76
    # dnsmasq-pi-hole-2.87test3
    # dnsmasq-pi-hole-2.87test4-6
    # dnsmasq-pi-hole-v2.87rc1
    # dnsmasq-pi-hole-v2.89-9461807
    # dnsmasq-pi-hole-v2.90
    # dnsmasq-pi-hole-v2.90+1
    # dnsmasq-2.78-23-g9e09429
    # dnsmasq-pi-hole-v2.92test11
    # dnsmasq-UNKNOWN
    if( banner =~ "^dnsmasq" || banner =~ "^PowerDNS Authoritative Server" || banner =~ "^PowerDNS Recursor" || "jenkins@autotest.powerdns.com" >< banner || banner =~ "^Knot DNS" ) {
      # Doesn't have any OS info so just register Linux/Unix
      os_register_and_report( os:"Linux/Unix", cpe:"cpe:/o:linux:kernel", banner_type:BANNER_TYPE, port:port, proto:proto, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      # Only continue here for the pattern without OS info so we register an unknown OS down below if there is any additional data in the banner we want to know
      if( banner == "dnsmasq" || banner == "dnsmasq-UNKNOWN" ||
          egrep( pattern:"^dnsmasq-(pi-hole-)?v?([0-9.]+((rc|test)?[0-9+-]+)?)$", string:banner ) ||
          egrep( pattern:"^PowerDNS Authoritative Server ([0-9.]+)$", string:banner ) ||
          egrep( pattern:"^PowerDNS Recursor ([0-9.]+)$", string:banner ) ||
          egrep( pattern:"^Knot DNS ([0-9.]+)$", string:banner ) ) {
        continue;
      }
    }
    os_register_unknown_banner( banner:banner, banner_type_name:BANNER_TYPE, banner_type_short:"dns_banner", port:port, proto:proto );
  }
}

exit( 0 );
