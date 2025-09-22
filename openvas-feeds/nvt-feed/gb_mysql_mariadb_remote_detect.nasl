# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100152");
  script_version("2025-09-09T05:38:49+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-09-09 05:38:49 +0000 (Tue, 09 Sep 2025)");
  script_tag(name:"creation_date", value:"2009-04-23 19:21:19 +0000 (Thu, 23 Apr 2009)");
  script_name("MariaDB / Oracle MySQL Detection (MySQL Protocol)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_dependencies("find_service1.nasl", "sw_sphinxsearch_detect.nasl");
  script_require_ports("Services/mysql", 3306);

  script_tag(name:"summary", value:"MySQL protocol-based detection of MariaDB / Oracle MySQL.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("port_service_func.inc");
include("mysql.inc");
include("cpe.inc");
include("host_details.inc");
include("byte_func.inc");

set_byte_order(BYTE_ORDER_LITTLE_ENDIAN);

port = service_get_port( default:3306, proto:"mysql" );

# Don't detect MySQL / MariaDB on SphinxQL
if( get_kb_item( "sphinxsearch/" + port + "/detected" ) )
  exit( 0 );

if( ! soc = open_sock_tcp( port ) )
  exit( 0 );

buf = mysql_recv_server_handshake( socket:soc );
close( soc );

if( ord( buf[0] ) == 255 ) { # connect not allowed

  errno = ord( buf[2] ) << 8 | ord( buf[1] );

  if( errno == ER_HOST_IS_BLOCKED || errno == ER_HOST_NOT_PRIVILEGED ) {

    # nb: Don't use the first key in "script_exclude_keys" because there might be multiple
    # installations where only one is blocking the access.
    set_kb_item( name:"mysql_mariadb/blocked", value:TRUE );
    set_kb_item( name:"mysql_mariadb/" + port + "/blocked", value:TRUE );

    # nb: Deprecated, should be dropped once all VTs using these have been updated to use the new style.
    set_kb_item( name:"MySQL/" + port + "/blocked", value:TRUE );

    if( errno == ER_HOST_IS_BLOCKED ) {

      extra = "Scanner received a ER_HOST_IS_BLOCKED ";

      # Host 'xxx' is blocked because of many connection errors; unblock with 'mariadb-admin flush-hosts'
      if( "mariadb-admin" >< buf ) {
        MariaDB_FOUND = TRUE;
        extra += 'error from the remote MariaDB server.\nSome ';
        extra += "tests may fail. Run 'mariadb-admin flush-hosts' to ";
        extra += "enable scanner access to this host.";
      }

      # Host 'xxx' is blocked because of many connection errors; unblock with 'mysqladmin flush-hosts'
      # nb: Older MariaDB versions had used the same string as MySQL.
      else if( "mysqladmin" >< buf ) {
        MySQL_FOUND = TRUE;
        extra += 'error from the remote MySQL server.\nSome ';
        extra += "tests may fail. Run 'mysqladmin flush-hosts' to ";
        extra += "enable scanner access to this host.";
      }

      else {
        # nb: We're still setting the MySQL CPE / keys in this case below.
        MariaDB_or_MySQL_FOUND = TRUE;
        extra += 'error from the remote MySQL/MariaDB server.\nSome ';
        extra += "tests may fail. Run 'mysqladmin flush-hosts' or ";
        extra += "'mariadb-admin flush-hosts' to ";
        extra += "enable scanner access to this host.";
      }
    } else if( errno == ER_HOST_NOT_PRIVILEGED ) {

      extra = "Scanner received a ER_HOST_NOT_PRIVILEGED ";

      # Host 'xxx' is not allowed to connect to this MariaDB server
      if( "MariaDB" >< buf ) {
        MariaDB_FOUND = TRUE;
        extra += 'error from the remote MariaDB server.\nSome ';
        extra += "tests may fail. Allow the scanner to access the ";
        extra += "remote MariaDB server for better results.";
      }

      # Host 'xxx' is not allowed to connect to this MySQL server
      # nb: Older MariaDB versions had used the same string as MySQL.
      else if( "MySQL" >< buf ) {
        MySQL_FOUND = TRUE;
        extra += 'error from the remote MySQL server.\nSome ';
        extra += "tests may fail. Allow the scanner to access the ";
        extra += "remote MySQL server for better results.";
      }

      else {
        # nb: We're still setting the MySQL CPE / keys in this case below.
        MariaDB_or_MySQL_FOUND = TRUE;
        extra += 'error from the remote MySQL/MariaDB server.\nSome ';
        extra += "tests may fail. Allow the scanner to access the ";
        extra += "remote MySQL/MariaDB server for better results.";
      }
    }
  }
} else if( ord( buf[0] ) == 10 ) { # nb: connect allowed
  if( "MariaDB" >< buf )
    MariaDB_FOUND = TRUE;
  else
    MySQL_FOUND = TRUE;

  for( i = 1; i < strlen( buf ); i++ ) {
    # server_version is a Null-Terminated String
    if( ord( buf[i] ) != 0 )
      version += buf[i];
    else
      break;
  }
}

if( MySQL_FOUND || MariaDB_or_MySQL_FOUND ) {

  if( version ) {
    concluded = version;
    set_kb_item( name:"mysql_mariadb/full_banner/" + port, value:version );

    # nb: Used in 2012/gb_database_open_access_vuln.nasl to report an "Open" Database.
    # These keys should be only set if it was possible to grab the version without authentication.
    set_kb_item( name:"OpenDatabase/found", value:TRUE );
    set_kb_item( name:"oracle/mysql/" + port + "/open_accessible", value:TRUE );
  } else {
    version = "unknown";
  }

  set_kb_item( name:"oracle/mysql/detected", value:TRUE );
  set_kb_item( name:"mysql_mariadb/detected", value:TRUE );
  set_kb_item( name:"oracle/mysql/remote/detected", value:TRUE );
  set_kb_item( name:"mysql_mariadb/remote/detected", value:TRUE );
  set_kb_item( name:"oracle/mysql/" + port + "/detected", value:TRUE );
  set_kb_item( name:"mysql_mariadb/" + port + "/detected", value:TRUE );

  service_register( port:port, proto:"mysql" );

  # nb: Older NVD MySQL entries are using this CPE so we're registering the new and the only ones
  # but are only using the Oracle one in Vulnerability-VTs.
  cpe1 = build_cpe( value:version, exp:"^([0-9.]+-?[a-zA-Z]+?)", base:"cpe:/a:mysql:mysql:" );
  if( ! cpe1 )
    cpe1 = "cpe:/a:mysql:mysql";

  cpe2 = build_cpe( value:version, exp:"^([0-9.]+[a-zA-Z]+?)", base:"cpe:/a:oracle:mysql:" );
  if( ! cpe2 )
    cpe2 = "cpe:/a:oracle:mysql";

  install = port + "/tcp";

  register_product( cpe:cpe1, location:install, port:port, service:"mysql" );
  register_product( cpe:cpe2, location:install, port:port, service:"mysql" );

  log_message( data:build_detection_report( app:"Oracle MySQL",
                                            version:version,
                                            install:install,
                                            cpe:cpe2,
                                            concluded:concluded,
                                            extra:extra ),
               port:port );
}

if( MariaDB_FOUND ) {

  if( version ) {

    # MariaDB version 10.x and above is detected as 5.5.x-10.x-MariaDB, e.g.:
    #
    # 5.5.5-10.1.19-MariaDB
    # 5.5.5-10.5.21-MariaDB-0+deb11u1-log
    # 5.5.5-10.5.23-MariaDB-0+deb11u1-log
    # 5.5.5-10.11.6-MariaDB-0+deb12u1-log
    # 5.5.5-10.11.14-MariaDB-0+deb12u2-log
    #
    if( version =~ "([0-9.]+)-([0-9.]+)-([A-Za-z]+)?" ) {
      version = eregmatch( pattern:"([0-9.]+)-([0-9.]+)-", string:version );
      version = version[2];
    }

    # Regex for old MariaDB versions like e.g.:
    #
    # 5.5.49-MariaDB
    # 5.2.14-MariaDB-log
    #
    # but some (newer)? versions started to use the same again as well like e.g.:
    #
    # 10.2.44-MariaDB-1:10.2.44+maria~bionic
    # 10.4.28-MariaDB
    #
    else {
      version = eregmatch( pattern:"([0-9.]+)-", string:version );
      version = version[1];
    }

    # Regex to not print the changing buf with binary data in the report, buf is e.g.:
    #
    # 5.5.5-10.1.19-MariaDB
    # 5.5.49-MariaDB
    # 5.2.14-MariaDB-log
    # 10.2.44-MariaDB-1:10.2.44+maria~bionic
    #
    # nb: rnul:FALSE is used here as we want to end with the first \0x00 here.
    _concluded = eregmatch( string:buf, pattern:"([0-9.]+)(-([0-9.]+))?-.+", rnul:FALSE );
    if( _concluded[0] )
      concluded = _concluded[0];
    else
      concluded = buf;

    set_kb_item( name:"mysql_mariadb/full_banner/" + port, value:concluded );

    # nb: Used in 2012/gb_database_open_access_vuln.nasl to report an "Open" Database.
    # These keys should be only set if it was possible to grab the version without authentication.
    set_kb_item( name:"OpenDatabase/found", value:TRUE );
    set_kb_item( name:"mariadb/" + port + "/open_accessible", value:TRUE );

  } else {
    version = "unknown";
  }

  set_kb_item( name:"mariadb/detected", value:TRUE );
  set_kb_item( name:"mysql_mariadb/detected", value:TRUE );
  set_kb_item( name:"mariadb/remote/detected", value:TRUE );
  set_kb_item( name:"mysql_mariadb/remote/detected", value:TRUE );
  set_kb_item( name:"mariadb/" + port + "/detected", value:TRUE );
  set_kb_item( name:"mysql_mariadb/" + port + "/detected", value:TRUE );

  service_register( port:port, proto:"mysql" );

  cpe = build_cpe( value:version, exp:"^([0-9.]+-?[a-zA-Z]+?)", base:"cpe:/a:mariadb:mariadb:" );
  if( ! cpe )
    cpe = "cpe:/a:mariadb:mariadb";

  install = port + "/tcp";

  register_product( cpe:cpe, location:install, port:port, service:"mysql" );

  log_message( data:build_detection_report( app:"MariaDB",
                                            version:version,
                                            install:install,
                                            cpe:cpe,
                                            concluded:concluded,
                                            extra:extra ),
               port:port );
}

exit( 0 );
