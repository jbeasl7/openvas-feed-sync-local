# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902799");
  script_version("2025-09-09T05:38:49+0000");
  script_tag(name:"last_modification", value:"2025-09-09 05:38:49 +0000 (Tue, 09 Sep 2025)");
  script_tag(name:"creation_date", value:"2012-03-01 17:10:53 +0530 (Thu, 01 Mar 2012)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Database Open Access Information Disclosure Vulnerability");
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Databases");
  # nb: No need to add the "more specific" dependency gb_postgresql_consolidation.nasl for
  # PostgreSQL as gb_postgresql_tcp_detect.nasl is setting the required KB keys below.
  script_dependencies("oracle_tnslsnr_version.nasl", "gb_ibm_db2_das_detect.nasl",
                      "gb_postgresql_tcp_detect.nasl",
                      "gb_microsoft_sql_server_tcp_ip_listener_detect.nasl",
                      "gb_ibm_soliddb_detect.nasl", "gb_mysql_mariadb_remote_detect.nasl",
                      "secpod_open_tcp_ports.nasl", "gb_open_udp_ports.nasl");
  script_mandatory_keys("OpenDatabase/found");

  script_xref(name:"URL", value:"https://www.pcisecuritystandards.org/security_standards/index.php?id=pci_dss_v1-2.pdf");

  script_tag(name:"summary", value:"Various Database server might be prone to an information
  disclosure vulnerability if accessible to remote systems.");

  script_tag(name:"vuldetect", value:"Checks the result of various database server detections and
  evaluates their results.");

  script_tag(name:"insight", value:"The remote database server is not restricting direct access from
  remote systems.");

  script_tag(name:"impact", value:"Successful exploitation could allow an attacker to obtain
  sensitive information from the database.");

  script_tag(name:"affected", value:"- Oracle MySQL

  - MariaDB

  - IBM DB2

  - PostgreSQL

  - IBM solidDB

  - Oracle Database

  - Microsoft SQL Server");

  script_tag(name:"solution", value:"Restrict database access to remote systems. Please see the
  manual of the affected database server for more information.");

  script_tag(name:"solution_type", value:"Workaround");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("port_service_func.inc");
include("list_array_func.inc");

function is_oracle_db( port ) {

  local_var port, ver;

  ver = get_kb_item( "oracle_tnslsnr/" + port + "/version" );
  if( ver )
    return TRUE;
  else
    return FALSE;
}

function is_ibm_db2( port ) {

  local_var port, ibmVer;

  ibmVer = get_kb_item( "ibm/db2/das/" + port + "/version" );
  if( ibmVer )
    return TRUE;
  else
    return FALSE;
}

function is_postgre_sql( port ) {

  local_var port, psqlver;

  psqlver = get_kb_item( "PostgreSQL/Remote/" + port + "/Ver" );
  if( psqlver )
    return TRUE;
  else
    return FALSE;
}

function is_solid_db( port ) {

  local_var port, solidVer;

  solidVer = get_kb_item( "soliddb/" + port + "/version" );
  if( solidVer )
    return TRUE;
  else
    return FALSE;
}

function is_mssql( port ) {

  local_var port, mssql_rls;

  mssql_rls = get_kb_item( "microsoft/sqlserver/" + port + "/releasename" );
  if( mssql_rls )
    return TRUE;
  else
    return FALSE;
}

function is_mysql( port ) {

  local_var port, myVer;

  myVer = get_kb_item( "oracle/mysql/" + port + "/open_accessible" );
  if( myVer )
    return TRUE;
  else
    return FALSE;
}

function is_mariadb( port ) {

  local_var port, mariaVer;

  mariaVer = get_kb_item( "mariadb/" + port + "/open_accessible" );
  if( mariaVer )
    return TRUE;
  else
    return FALSE;
}

# nb: This function is already checking for get_port_state()
# and is returning an empty list if no port was found
ports = tcp_get_all_ports();
# Adding the default ports if unscanned_closed = no
ports = make_list_unique( ports, 5432, 1433, 1315, 3306, 1521 );

foreach port( ports ) {

  oracle_db = is_oracle_db( port:port );
  if( oracle_db ) {
    log_message( data:"Oracle database can be accessed by remote attackers", port:port );
    continue;
  }

  mysql = is_mysql( port:port );
  if( mysql ) {
    log_message( data:"Oracle MySQL can be accessed by remote attackers", port:port );
    continue;
  }

  mariadb = is_mariadb( port:port );
  if( mariadb ) {
    log_message( data:"MariaDB can be accessed by remote attackers", port:port );
    continue;
  }

  postgre_sql = is_postgre_sql( port:port );
  if( postgre_sql ) {
    log_message( data:"PostgreSQL database can be accessed by remote attackers", port:port );
    continue;
  }

  solid_db = is_solid_db( port:port );
  if( solid_db ) {
    log_message( data:"SolidDB can be accessed by remote attackers", port:port);
    continue;
  }

  mssql = is_mssql();
  if( mssql ) {
    log_message( data:"Microsoft SQL Server can be accessed by remote attackers", port:port );
    continue;
  }
}

# nb: This function is already checking for get_udp_port_state()
# and is returning an empty list if no port was found
udp_ports = udp_get_all_ports();
# Adding the default port if unscanned_closed_udp = no
udp_ports = make_list_unique( udp_ports, 523 );

foreach udp_port( udp_ports ) {
  ibm_db2 = is_ibm_db2( port:udp_port );
  if( ibm_db2 ) {
    log_message( data:"IBM DB2 can be accessed by remote attackers", port:udp_port, proto:"udp" );
    continue;
  }
}

exit( 0 );
