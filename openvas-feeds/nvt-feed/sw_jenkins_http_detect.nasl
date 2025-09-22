# SPDX-FileCopyrightText: 2015 SCHUTZWERK GmbH
# SPDX-FileCopyrightText: New/improved detection methods / pattern / code since 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.111001");
  script_version("2024-12-06T05:05:38+0000");
  script_tag(name:"last_modification", value:"2024-12-06 05:05:38 +0000 (Fri, 06 Dec 2024)");
  script_tag(name:"creation_date", value:"2015-03-02 12:00:00 +0100 (Mon, 02 Mar 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Jenkins Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 SCHUTZWERK GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "global_settings.nasl",
                      "gb_jenkins_cli_tcp_detect.nasl"); # nb: Included here so that only unknown services are registered below
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of the Jenkins automation server.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("host_details.inc");

port = http_get_port( default:8080 );

foreach dir( make_list_unique( "/", "/jenkins", http_cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" )
    dir = "";

  buf1 =  http_get_cache( item:dir + "/", port:port );
  if( buf1 )
    headers1 = http_extract_headers_from_response( data:buf1 );

  buf2 = http_get_cache( item:dir + "/login", port:port );

  if( "Welcome to Jenkins!" >< buf1 || "<title>Dashboard [Jenkins]</title>" >< buf1 || headers1 =~ "X-Jenkins\s*:" ||
      "<title>Jenkins</title>" >< buf2 || "<title>Sign in [Jenkins]</title>" >< buf2 || headers1 =~ "X-Jenkins-CLI-Port2?\s*:" ||
      # nb: This is on port 50000/tcp on newer versions (doubled newlines expected):
      #
      # HTTP/1.0 200 OK
      # Content-Type: text/plain;charset=UTF-8
      # X-Content-Type-Options: nosniff
      #
      #
      # Jenkins-Agent-Protocols: JNLP4-connect, Ping
      # Jenkins-Version: 2.487
      # Jenkins-Session: dc51a0eb
      # Client: 172.17.0.1
      # Server: 172.17.0.3
      # Remoting-Minimum-Version: 3107.v665000b_51092
      egrep( string:buf1, pattern:"^[Jj]enkins-[Vv]ersion\s*:\s*[0-9.]+", icase:FALSE )
    ) {

    version = "unknown";

    # e.g.
    # <a href="http://jenkins-ci.org/">Jenkins ver. 1.651.2</a>
    ver = eregmatch( pattern:"Jenkins ver\. ([0-9.]+)", string:buf1 );
    if( ! isnull( ver[1] ) )
      version = ver[1];

    if( version == "unknown" ) {
      # X-Jenkins: 1.651.2
      # X-Jenkins: 2.294
      ver = eregmatch( pattern:"X-Jenkins\s*:\s*([0-9.]+)", string:headers1, icase:TRUE );
      if( ! isnull( ver[1] ) )
        version = ver[1];
    }

    # nb: If a login is enabled the version isn't exposed via this pattern.
    if( version == "unknown" ) {
      ver = eregmatch( pattern:"Jenkins ver\. ([0-9.]+)", string:buf2 );
      if( ! isnull( ver[1] ) )
        version = ver[1];
    }

    # nb: This is on port 50000/tcp on newer Jenkins versions
    if( version == "unknown" ) {
      # Jenkins-Version: 2.487
      ver = eregmatch( pattern:"[Jj]enkins-[Vv]ersion\s*:\s*([0-9.]+)", string:buf1 );
      if( ! isnull( ver[1] ) )
        version = ver[1];
    }

    # nb: set KB item for LTS version of Jenkins to differentiate it from weekly version in the VTs
    # LTS: x.x.x - Weekly: x.x
    if( version && version != "unknown" ) {
      if( version =~ "^[0-9]+\.[0-9]+\.[0-9]+" ) {
        set_kb_item( name:"jenkins/" + port + "/is_lts", value:TRUE );
      }
    }

    set_kb_item( name:"jenkins/detected", value:TRUE );
    set_kb_item( name:"jenkins/http/detected", value:TRUE );
    set_kb_item( name:"jenkins/http/port", value:port );
    set_kb_item( name:"jenkins/http/" + port + "/location", value:install );

    if( version != "unknown" ) {
      set_kb_item( name:"jenkins/http/" + port + "/version", value:version );
      set_kb_item( name:"jenkins/http/" + port + "/concluded", value:ver[0] );
    }

    # e.g.
    # X-Jenkins-CLI-Port: 40569
    # X-Jenkins-CLI2-Port: 40569
    #
    # nb:
    # - There is also a "basic" detection pattern for this port included in find_service6.nasl
    # - We also want to "register" the service only if it is unknown so far
    #
    cli_port = eregmatch( pattern:"X-Jenkins-CLI-Port\s*:\s*([0-9]+)", string:headers1, icase:TRUE );
    if( ! isnull( cli_port[1] ) ) {
      if( get_port_state( cli_port[1] ) && service_is_unknown( port:cli_port[1] ) ) {
        service_register( port:cli_port[1], proto:"jenkins_cli" );
        set_kb_item( name:"jenkins/jenkins_cli/detected", value:TRUE );
        set_kb_item( name:"jenkins/jenkins_cli/tcp/detected", value:TRUE );
        set_kb_item( name:"jenkins/jenkins_cli/port", value:cli_port[1] );
        set_kb_item( name:"jenkins/jenkins_cli/" + cli_port[1] + "/version", value:"unknown" );
        set_kb_item( name:"jenkins/jenkins_cli/" + cli_port[1] + "/concluded", value:cli_port[0] );
      }
    }

    cli_port2 = eregmatch( pattern:"X-Jenkins-CLI2-Port\s*:\s*([0-9]+)", string:headers1, icase:TRUE );
    # nb: Both ports might be the same (see above), the check below makes sure that we're not register / report the same port twice.
    if( ! isnull( cli_port2[1] ) && cli_port2[1] != cli_port[1] ) {
      if( get_port_state( cli_port2[1] ) && service_is_unknown( port:cli_port2[1] ) ) {
        service_register( port:cli_port2[1], proto:"jenkins_cli" );
        set_kb_item( name:"jenkins/jenkins_cli/detected", value:TRUE );
        set_kb_item( name:"jenkins/jenkins_cli/tcp/detected", value:TRUE );
        set_kb_item( name:"jenkins/jenkins_cli/port", value:cli_port2[1] );
        set_kb_item( name:"jenkins/jenkins_cli/" + cli_port2[1] + "/version", value:"unknown" );
        set_kb_item( name:"jenkins/jenkins_cli/" + cli_port2[1] + "/concluded", value:cli_port2[0] );
      }
    }

    # This can be used if a specific VT requires a valid user. Note that this
    # could be protected via a login.
    # nb: The "fullName" is only some alias which might be different from the actual login
    # we need to gather and save here.
    req = http_get( item:dir + "/asynchPeople/api/xml", port:port );
    buf = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );
    if( buf =~ "^<people _class=" || "<absoluteUrl>" >< buf || "<fullName>" >< buf ) {

      # Anonymous read is enabled
      set_kb_item( name:"jenkins/" + port + "/anonymous_read_enabled", value:TRUE );
      set_kb_item( name:"jenkins/" + port + "/" + install + "/anonymous_read_enabled", value:TRUE );
      set_kb_item( name:"jenkins/anonymous_read_enabled", value:TRUE );

      users = split( buf, sep:"</user>", keep:FALSE );
      foreach user( users ) {
        _user = eregmatch( pattern:"<absoluteUrl>[^>]+/user/([^>]+)</absoluteUrl>", string:user, icase:FALSE );
        if( _user[1] )
          set_kb_item( name:"jenkins/" + port + "/user_list", value:_user[1] );
      }
    }

    # See e.g. https://javadoc.jenkins.io/hudson/security/WhoAmI.html
    url = dir + "/whoAmI/";
    req = http_get( item:url, port:port );
    buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );
    if( buf =~ "^HTTP/1\.[01] 200" && ( "<title>Who Am I [Jenkins]</title>" >< buf || "<td>IsAuthenticated" >< buf ) ) {
      set_kb_item( name:"jenkins/" + port + "/whoami_available", value:TRUE );
      set_kb_item( name:"jenkins/" + port + "/" + install + "/whoami_available", value:TRUE );
      set_kb_item( name:"jenkins/" + port + "/" + install + "/whoami_url", value:http_report_vuln_url( port:port, url:url, url_only:TRUE ) );
      set_kb_item( name:"jenkins/whoami_available", value:TRUE );
    }

    exit( 0 );
  }
}

exit( 0 );
