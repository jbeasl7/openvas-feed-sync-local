# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810317");
  script_version("2023-07-12T05:05:04+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-12 05:05:04 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-12-23 11:51:30 +0530 (Fri, 23 Dec 2016)");

  script_name("Apache Hadoop Detection (HTTP)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 50070);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Apache Hadoop.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("cpe.inc");
include("host_details.inc");

port = http_get_port( default:50070 );

# dfshealth.jsp is the (Legacy UI), /dfshealth.html for newer versions
# "SoftwareVersion" : "2.6.0-cdh5.8.2",
# "SoftwareVersion" : "2.7.2",
# <tr><td class='col1'>Version:</td><td>2.6.0-cdh5.8.2, 9abce7e9ea82d98c14606e7ccc7fa3aa448f6e90</td></tr>
# <tr> <td id="col1"> Version: <td> 0.20.2-cdh3u3, 318bc781117fa276ae81a3d111f5eeba0020634f
#
# ResourceManager (default on port 8088)
# <th>Hadoop version:</th><td>2.9.1 from ...</td>
urls =
make_array( "/dfshealth.jsp", '> *Version:( |</td>)?<td> *([0-9\\.]+)([0-9a-z.\\-]+)?,',
            "/dfshealth.html", '"SoftwareVersion" : "([0-9.]+)([0-9a-z.\\-]+)?",',
            "/cluster/cluster", "Hadoop version:\s+(</th>\s+)?<td>\s+([0-9\.]+)" );

foreach url( keys( urls ) ) {

  res = http_get_cache( item:url, port:port );

  if( res =~ "^HTTP/1\.[01] 200" &&
      ( ">Cluster Summary<" >< res && ( "Apache Hadoop<" >< res || ">Hadoop<" >< res ) ) || # dfshealth.jsp
      ( "<title>Namenode information</title>" >< res && ">Hadoop</div>" >< res ) || # dfshealth.html
      ( "About the Cluster" >< res && "Hadoop version" >< res) # cluster/cluster
    ) {

    conclUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );
    install = "/";
    version = "unknown";
    extra = "";
    secureModeDisabled = FALSE;

    if( url == "/dfshealth.html" ) {
      url2 = "/jmx?qry=Hadoop:service=NameNode,name=NameNodeInfo";
      req = http_get( item:url2, port:port );
      res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );
      if( res =~ "^HTTP/1\.[01] 200" ) conclUrl = http_report_vuln_url( port:port, url:url2, url_only:TRUE );

      vers = eregmatch( pattern:urls[url], string:res );
      if( vers[1] ) version = vers[1];
      set_kb_item( name:"Apache/Hadoop/Installed", value:TRUE );
    }
    else {
      vers = eregmatch( pattern:urls[url], string:res );
      if( vers[2] ) version = vers[2];
      set_kb_item( name:"Apache/Hadoop/Installed", value:TRUE );
    }

    if( ">Security is <em>OFF</em>" >< res ) {
      secureModeDisabled = TRUE;
    } else {
      url3 = "/jmx?qry=Hadoop:service=NameNode,name=NameNodeStatus";
      req = http_get( item:url3, port:port );
      res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );
      # Second try for checking the Secure Mode
      if( res =~ "^HTTP/1\.[01] 200" && '"SecurityEnabled" : false,' >< res )
        secureModeDisabled = TRUE;
    }

    if( secureModeDisabled ) {
      extra = "Secure Mode is not enabled.";
      set_kb_item( name:"Apache/Hadoop/SecureMode/Disabled", value:TRUE );
      set_kb_item( name:"Apache/Hadoop/SecureMode/" + port + "/Disabled", value:TRUE );
    }

    cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:apache:hadoop:" );
    if( ! cpe )
      cpe = "cpe:/a:apache:hadoop";

    register_product( cpe:cpe, location:install, port:port, service:"www" );

    log_message( data:build_detection_report( app:"Apache Hadoop",
                                              version:version,
                                              install:install,
                                              cpe:cpe,
                                              concludedUrl:conclUrl,
                                              extra:extra,
                                              concluded:vers[0] ),
                 port:port );

    exit( 0 ); # Some versions have both files so exit after the first hit
  }
}

exit( 0 );
