# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105809");
  script_version("2023-09-07T05:05:21+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-09-07 05:05:21 +0000 (Thu, 07 Sep 2023)");
  script_tag(name:"creation_date", value:"2016-07-13 16:11:18 +0200 (Wed, 13 Jul 2016)");
  script_name("Docker Detection (HTTP REST API)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 2375);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP REST API based detection of Docker.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");
include("os_func.inc");

SCRIPT_DESC = "Docker Detection (HTTP REST API)";
OS_BANNER_TYPE = "Docker HTTP REST API OS banner";

port = http_get_port( default:2375 );

url = "/version";
buf = http_get_cache( item:url, port:port );

if( ! buf || buf !~ "^HTTP/1\.[01] 200" || buf !~ "Content-Type\s*:\s*application/json" || "ApiVersion" >!< buf || "Version" >!< buf )
  exit( 0 );

rep_url = http_report_vuln_url( port:port, url:url, url_only:TRUE );
accessible_endpoints = rep_url;

vers = "unknown";
rep_vers = "unknown";
install = port + "/tcp";
cpe = "cpe:/a:docker:docker";

set_kb_item( name:"docker/installed", value:TRUE );
set_kb_item( name:"docker/detected", value:TRUE );
set_kb_item( name:"docker/http/detected", value:TRUE );
set_kb_item( name:"docker/http/rest-api/detected", value:TRUE );
# nb:
# - Currently the KB keys are set at the same time like the ones above but might be changed / moved
#   in the future if there are e.g. some "secure" mode directly in docker
# - https://docs.docker.com/engine/api/v1.43/#section/Authentication mentions "Authentication" but
#   this is for the Authentication to Remote Docker Registries
set_kb_item( name:"docker/http/rest-api/noauth", value:TRUE );
set_kb_item( name:"docker/http/rest-api/" + port + "/noauth", value:TRUE );

version = eregmatch( pattern:'Version"\\s*:\\s*"([0-9]+[^"]+)",', string:buf );
if( ! isnull( version[1] ) ) {
  vers = version[1];
  concluded = version[0];
  cpe += ":" + vers;
  rep_vers = vers;
  replace_kb_item( name:"docker/version", value:vers );
}

av = eregmatch( pattern:'ApiVersion"\\s*:\\s*"([0-9]+[^"]+)",', string:buf );
if( ! isnull( av[1] ) ) {
  apiversion = av[1];
  set_kb_item( name:"docker/apiversion", value:apiversion );
  rep_vers += " (ApiVersion: " + apiversion + ")";
}

# {"Version":"1.9.1","ApiVersion":"1.21","GitCommit":"a34a1d5","GoVersion":"go1.4.2","Os":"linux","Arch":"amd64","KernelVersion":"3.16.7-35-desktop"}
# {"Platform":{"Name":""},"Components":[{"Name":"Engine","Version":"20.10.24+dfsg1","Details":{"ApiVersion":"1.41","Arch":"amd64","BuildTime":"2023-05-18T08:38:34.000000000+00:00","Experimental":"false","GitCommit":"5d6db84","GoVersion":"go1.19.8","KernelVersion":"6.3.0-1-amd64","MinAPIVersion":"1.12","Os":"linux"}},{"Name":"containerd","Version":"1.6.20~ds1","Details":{"GitCommit":"1.6.20~ds1-1+b1"}},{"Name":"runc","Version":"1.1.5+ds1","Details":{"GitCommit":"1.1.5+ds1-1+b1"}},{"Name":"docker-init","Version":"0.19.0","Details":{"GitCommit":""}}],"Version":"20.10.24+dfsg1","ApiVersion":"1.41","MinAPIVersion":"1.12","GitCommit":"5d6db84","GoVersion":"go1.19.8","Os":"linux","Arch":"amd64","KernelVersion":"6.3.0-1-amd64","BuildTime":"2023-05-18T08:38:34.000000000+00:00"}
# {"Platform":{"Name":"Mirantis Container Runtime"},"Components":[{"Name":"Engine","Version":"20.10.7","Details":{"ApiVersion":"1.41","Arch":"amd64","BuildTime":"08/19/2021 18:53:20","Experimental":"false","GitCommit":"e1bf5b9c13","GoVersion":"go1.13.15","KernelVersion":"10.0 17763 (17763.1.amd64fre.rs5_release.180914-1434)","MinAPIVersion":"1.24","Os":"windows"}}],"Version":"20.10.7","ApiVersion":"1.41","MinAPIVersion":"1.24","GitCommit":"e1bf5b9c13","GoVersion":"go1.13.15","Os":"windows","Arch":"amd64","KernelVersion":"10.0 17763 (17763.1.amd64fre.rs5_release.180914-1434)","BuildTime":"08/19/2021 18:53:20"}

# nb: Using egrep() here as the previously used "(\{[^}]?+\})" had extracted "too less"
full_json = egrep( pattern:"(\{[^}]+\})", string:buf );
if( ! isnull( full_json ) ) {
  full_json = chomp( full_json );
  set_kb_item( name:"docker/full_json", value:full_json );
  if( concluded )
    concluded += '\n';
  concluded += full_json;
}

# "Os":"linux"
# "Os":"windows"
host_os = eregmatch( string:buf, pattern:'"Os"\\s*:\\s*"([^"]+)"', icase:FALSE );
if( host_os[1] ) {
  concl = host_os[0];
  host_os_version = "unknown";
  host_os_kernel_vers = eregmatch( string:buf, pattern:'"KernelVersion"\\s*:\\s*"([^"]+)"', icase:FALSE );
  if( host_os_kernel_vers[1] ) {
    host_os_version = host_os_kernel_vers[1];
    concl += " and " + host_os_kernel_vers[0];
  }

  # nb:
  # - Using "=~" here as we don't know if this was e.g. "Linux" in the past
  # - For now we're only extracting the Kernel Version for Linux but might want to do the same for
  #   Windows in the future as well
  if( host_os =~ "linux" ) {
    os_register_and_report( os:"Linux/Unix", version:host_os_version, cpe:"cpe:/o:linux:kernel", banner_type:OS_BANNER_TYPE, port:port, banner:concl, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else if( host_os =~ "windows" )
    os_register_and_report( os:"Microsoft Windows", cpe:"cpe:/o:microsoft:windows", banner_type:OS_BANNER_TYPE, port:port, banner:concl, desc:SCRIPT_DESC, runs_key:"windows" );
  else
    os_register_unknown_banner( banner:concl, banner_type_name:OS_BANNER_TYPE, banner_type_short:"docker_os_banner", port:port );

  set_kb_item( name:"docker/host_os", value:host_os );
}

register_product( cpe:cpe, location:install, port:port, service:"www" );

if( ! apiversion )
  apiversion = "1.19";

# Notes from https://docs.docker.com/engine/api/v1.43/#section/Versioning:
# - For example, calling /info is the same as calling /v1.43/info
# - Using the API without a version-prefix is deprecated and will be removed in a future release
url = "/v" + apiversion + "/containers/json?all=1";
req = http_get( item:url, port:port );
buf = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );

if( "Id" >< buf && "ImageID" >< buf && "Names" >< buf ) {

  accessible_endpoints += '\n' + http_report_vuln_url( port:port, url:url, url_only:TRUE );

  if( "}},{" >< buf )
    sep = "}},{";
  else if( "]},{" >< buf )
    sep = "]},{";

  if( sep )
    parts = split( buf, sep:sep, keep:TRUE );
  else
    parts = split( buf );

  foreach container( parts ) {

    _id = eregmatch( pattern:'"Id"\\s*:\\s*"([^"]+)"', string:container );
    if( ! isnull( _id[1] ) )
      id = _id[1];

    _name = eregmatch( pattern:'"Names"\\s*:\\s*\\["/([^"]+)"', string:container );
    if( ! isnull( _name[1] ) )
      name = _name[1];

    _image = eregmatch( pattern:'"Image"\\s*:\\s*"([^"]+)"', string:container );
    if( ! isnull( _image[1] ) )
      image = _image[1];

    _status = eregmatch( pattern:'"Status"\\s*:\\s*"([^"]+)"', string:container );
    if( ! isnull( _status[1] ) )
      status = _status[1];

    if( ! status )
      status = "unknown";

    ports = "";

    p = eregmatch( pattern:'"Ports"\\s*:\\s*\\[(.*)\\]', string:container );
    if( ! isnull( p[1] ) ) {

      _p = split( p[1], sep:"},{", keep:FALSE );

      foreach ip( _p ) {
        _ip       = eregmatch( pattern:'"IP"\\s*:\\s*"([^"]+)"', string:ip );
        _privport = eregmatch( pattern:'"PrivatePort"\\s*:\\s*([0-9-]+),', string:ip );
        _pupport  = eregmatch( pattern:'"PublicPort"\\s*:\\s*([0-9-]+),', string:ip );
        _type     = eregmatch( pattern:'"Type"\\s*:\\s*"([^"]+)"', string:ip );

        if( ! _ip[1] || ! _privport[1] || ! _pupport[1] || ! _type[1] )
          continue;

        ports += _ip[1] + ":" + _privport[1] + "->" + _pupport[1] + "/" + _type[1] + ", ";
      }
    }

    if( ! id || ! name || ! image )
      continue;

    set_kb_item( name:"docker/remote/container/" + id + "/id", value:id );
    set_kb_item( name:"docker/remote/container/" + id + "/name", value:name );
    set_kb_item( name:"docker/remote/container/" + id + "/image", value:image );
    set_kb_item( name:"docker/remote/container/" + id + "/state", value:status );

    if( status !~ "^Up " )
      continue;

    cdata += "Name:  " + name + '\n' +
             "ID:    " + id + '\n' +
             "Image  " + image + '\n';

    if( ports && ports != "" ) {
      cdata += "Ports: " + ports + '\n';
      set_kb_item( name:"docker/remote/container/" + id + "/ports", value:ports );
    }
    else
      cdata += 'Ports: N/A\n';

    cdata += '\n';
  }
}

# nb: For reporting in 2023/docker/gb_docker_http_rest_api_wan_access.nasl
set_kb_item( name:"docker/http/rest-api/" + port + "/accessible_endpoints", value:accessible_endpoints );

report = build_detection_report( app:"Docker", version:rep_vers, install:install, cpe:cpe, concluded:concluded, concludedUrl:rep_url );

if( cdata ) {
  set_kb_item( name:"docker/container/present", value:TRUE );
  report += '\n\nThe following containers were detected running on the remote host:\n\n' + cdata;
}

log_message( port:port, data:chomp( report ) );

exit( 0 );
