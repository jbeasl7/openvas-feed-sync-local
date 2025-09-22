# SPDX-FileCopyrightText: 2009 Greenbone AG
# SPDX-FileCopyrightText: 2009 LSS
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100288");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2023-10-13T05:06:10+0000");
  script_tag(name:"last_modification", value:"2023-10-13 05:06:10 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2009-10-05 19:43:01 +0200 (Mon, 05 Oct 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("CVS pserver Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Service detection");
  script_copyright("Copyright (C) 2009 Greenbone AG / LSS");
  script_dependencies("find_service2.nasl");
  script_require_ports("Services/cvspserver", 2401);

  script_tag(name:"summary", value:"This script retrieves the version of CVS pserver.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("port_service_func.inc");

function scramble(pass) {
# see http://www.delorie.com/gnu/docs/cvs/cvsclient_4.html
# for scramble information

 local_var x, scrambled, c;

# character substitution table
 c[33] = 120;   # !
 c[34] = 53;    # "
 c[37] = 109;   # %
 c[38] = 72;    # &
 c[39] = 108;   # '
 c[40] = 70;    # (
 c[41] = 64;    # )
 c[42] = 76;    # *
 c[43] = 67;    # +
 c[44] = 116;   # ,
 c[45] = 74;    # -
 c[46] = 68;    # .
 c[47] = 87;    # /
 c[48] = 111;   # 0
 c[49] = 52;    # 1
 c[50] = 75;    # 2
 c[51] = 119;   # 3
 c[52] = 49;    # 4
 c[53] = 34;    # 5
 c[54] = 82;    # 6
 c[55] = 81;    # 7
 c[56] = 95;    # 8
 c[57] = 65;    # 9
 c[58] = 112;   # :
 c[59] = 86;    # ;
 c[60] = 118;   # <
 c[61] = 110;   # =
 c[62] = 122;   # >
 c[63] = 105;   # ?
 c[65] = 57;    # A
 c[66] = 83;    # B
 c[67] = 43;    # C
 c[68] = 46;    # D
 c[69] = 102;   # E
 c[70] = 40;    # F
 c[71] = 89;    # G
 c[72] = 38;    # H
 c[73] = 103;   # I
 c[74] = 45;    # J
 c[75] = 50;    # K
 c[76] = 42;    # L
 c[77] = 123;   # M
 c[78] = 91;    # N
 c[79] = 35;    # O
 c[80] = 125;   # P
 c[81] = 55;    # Q
 c[82] = 54;    # R
 c[83] = 66;    # S
 c[84] = 124;   # T
 c[85] = 126;   # U
 c[86] = 59;    # V
 c[87] = 47;    # W
 c[88] = 92;    # X
 c[89] = 71;    # Y
 c[90] = 115;   # Z
 c[95] = 56;    # _
 c[97] = 121;   # a
 c[98] = 117;   # b
 c[99] = 104;   # c
 c[100] = 101;  # d
 c[101] = 100;  # e
 c[102] = 69;   # f
 c[103] = 73;   # g
 c[104] = 99;   # h
 c[105] = 63;   # i
 c[106] = 94;   # j
 c[107] = 93;   # k
 c[108] = 39;   # l
 c[109] = 37;   # m
 c[110] = 61;   # n
 c[111] = 48;   # o
 c[112] = 58;   # p
 c[113] = 113;  # q
 c[114] = 32;   # r
 c[115] = 90;   # s
 c[116] = 44;   # t
 c[117] = 98;   # u
 c[118] = 60;   # v
 c[119] = 51;   # w
 c[120] = 33;   # x
 c[121] = 97;   # y
 c[122] = 62;   # z

 for (x=0; x<strlen(pass); x++) {
  scrambled += raw_string(c[ord(pass[x])]);
 }

 return scrambled;
}

port = service_get_port( default:2401, proto:"cvspserver" );

logins    = make_list( "anonymous", "anoncvs" );
passwords = make_list( "", "anoncvs", "anon" );

foreach dir( make_list( "/var/lib/cvsd/", "/cvs", "/cvsroot", "/home/ncvs", "/usr/local/cvs", "/u/cvs", "/usr/local/cvsroot" ) ) {

  foreach login( logins ) {

    foreach password( passwords ) {

      soc = open_sock_tcp( port );
      if( ! soc ) continue;

      req = string( "BEGIN AUTH REQUEST\n", dir, "\n", login,"\n", "A", scramble(password),"\n", "END AUTH REQUEST\n" );
      send( socket:soc, data:req );
      buf = recv_line( socket:soc, length:4096 );

      if( "I LOVE YOU" >!< buf ) {
        close( soc );
        continue;
      }

      set_kb_item( name:"cvs/" + port + "/login", value:login );
      set_kb_item( name:"cvs/" + port + "/pass", value:password );
      set_kb_item( name:"cvs/" + port + "/dir", value:dir );

      send( socket:soc, data:string("Root ", dir, "\nversion\n") );
      buf = recv_line( socket:soc, length:4096 );
      close( soc );

      if( egrep( string:buf, pattern:"CVS", icase:TRUE ) ) {

        install = port + "/tcp";
        version = "unknown";

        vers = eregmatch( string:buf, pattern:"([0-9.]+)" );

        if( ! isnull( vers[1] ) )
          version = vers[1];

        service_register( port:port, proto:"cvspserver" );
        set_kb_item( name:"cvs/" + port + "/version", value:version );
        set_kb_item( name:"cvspserver/detected", value:TRUE );

        register_and_report_cpe( app:"CVS pserver", ver:version, concluded:vers[0], base:"cpe:/a:cvs:cvs:", expr:"^([0-9.]+)", insloc:install, regPort:port );
        exit( 0 );
      }
    }
  }
}

exit(0);
