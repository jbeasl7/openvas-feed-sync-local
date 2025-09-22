# SPDX-FileCopyrightText: 2009 Christian Eric Edjenguele
# SPDX-FileCopyrightText: New / improved (detection) code since 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.101018");
  script_version("2025-08-07T05:44:51+0000");
  script_tag(name:"last_modification", value:"2025-08-07 05:44:51 +0000 (Thu, 07 Aug 2025)");
  script_tag(name:"creation_date", value:"2009-04-01 22:29:14 +0200 (Wed, 01 Apr 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Microsoft Windows SharePoint Services (WSS) / Microsoft SharePoint Team Services Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Christian Eric Edjenguele");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "global_settings.nasl",
                      "gb_microsoft_iis_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://learn.microsoft.com/en-us/openspecs/sharepoint_protocols/ms-fpse/5d8827c8-3b7d-41d5-a893-8d7bd1be4bb4");

  script_tag(name:"summary", value:"HTTP based detection of Microsoft Windows SharePoint Services
  (WSS) / Microsoft SharePoint Team Services.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("cpe.inc");
include("host_details.inc");

port = http_get_port( default:80 );

if( ! http_can_host_asp( port:port ) )
  exit( 0 );

# nb:
# - Request a non existent random aspx page and some additional ones for trying to get the full
#   banner
# - The "/_vti_bin/*" seems to be from FrontPage but we have seen systems exposing only the banner
#   below on these endpoints (Proxy setup maybe?)
# - "/" is included as a last fallback as it should be already cached in the KB, is usually also
#   exposing the banner and could be used if any of the previous requests failed
urls = make_list(
  "/vt-test-non-existent.aspx",
  "/_vti_bin/shtml.dll",
  "/_vti_bin/shtml.exe",
  "/_vti_bin/",
  "/"
);

# Server: Microsoft-IIS/6.0
# Server: Microsoft-IIS/8.5
# Server: Microsoft-IIS/10.0
iisPattern = "Server\s*:\s*(Microsoft-)?IIS/([0-9.]+)";

# MicrosoftSharePointTeamServices: 6.0.2.6568
# MicrosoftSharePointTeamServices: 12.0.0.4518
# MicrosoftSharePointTeamServices: 15.0.0.4701
# MicrosoftSharePointTeamServices: 14.0.0.7175
# MicrosoftSharePointTeamServices: 16.0.0.10337
mstsPattern = "MicrosoftSharePointTeamServices\s*:\s*([0-9.]+)";

# X-SharePointHealthScore: 0
# Value is an integer between 0 and 10, see e.g.:
# https://learn.microsoft.com/en-us/openspecs/sharepoint_protocols/ms-wsshp/c60ddeb6-4113-4a73-9e97-26b5c3907d33
healthPattern = "X-SharePointHealthScore\s*:\s*([0-9]+)";

# X-Powered-By: ASP.NET
xPoweredByPattern = "X-Powered-By\s*:\s*([a-zA-Z.]+)";

# X-AspNet-Version: 4.0.30319
# X-AspNet-Version: 2.0.50727
aspNetPattern = "X-AspNet-Version\s*:\s*([0-9.]+)";

msts_base_cpe = "cpe:/a:microsoft:sharepoint_team_services";
wss_base_cpe = "cpe:/a:microsoft:sharepoint_services";

install = "/";

host = http_host_name( dont_add_port:TRUE );

foreach url( urls ) {

  # nb: Don't use http_get_remote_headers() as some servers might not respond to that on the
  # specific endpoints.
  if( ! res = http_get_cache( item:url, port:port ) )
    continue;

  # nb: One of these needs to be always there, otherwise we don't want to report here...
  if( ! ( tmp = egrep( pattern:"^(" + mstsPattern + "|" + healthPattern + ")", string:res, icase:TRUE ) ) )
    continue;

  mstsVers = eregmatch( pattern:mstsPattern, string:tmp, icase:TRUE );
  healtValue = eregmatch( pattern:healthPattern, string:tmp, icase:TRUE );
  if( ! mstsVers[1] && ! healtValue[1] )
    continue;

  concludedUrl = "  " + http_report_vuln_url( port:port, url:url, url_only:TRUE );

  mstsVersion = "unknown";
  if( mstsVers[1] ) {
    mstsVersion = mstsVers[1];
    concluded = "  " + mstsVers[0];
    mstsConcluded = "  " + concluded;
  }

  if( healtValue[1] ) {
    if( concluded )
      concluded += '\n';
    concluded += "  " + healtValue[0];
  }

  if( tmp = egrep( pattern:"^" + iisPattern, string:res, icase:TRUE ) )
    iisBanner = eregmatch( pattern:iisPattern, string:tmp, icase:TRUE );

  if( tmp = egrep( pattern:"^" + xPoweredByPattern, string:res, icase:TRUE ) )
    xPoweredBy = eregmatch( pattern:xPoweredByPattern, string:tmp, icase:TRUE );

  if( tmp = egrep( pattern:"^" + aspNetPattern, string:res, icase:TRUE ) )
    aspNetVersion = eregmatch( pattern:aspNetPattern, string:tmp, icase:TRUE );

  set_kb_item( name:"microsoft/windows_sharepoint_team_services/detected", value:TRUE );
  set_kb_item( name:"microsoft/windows_sharepoint_team_services/http/detected", value:TRUE );

  set_kb_item( name:"microsoft/windows_sharepoint_team_services/http/" + host + "/" + port + "/concluded", value:concluded );
  set_kb_item( name:"microsoft/windows_sharepoint_team_services/http/" + host + "/" + port + "/concludedUrl", value:concludedUrl );

  set_kb_item( name:"microsoft/spts_or_iis/detected", value:TRUE );
  set_kb_item( name:"microsoft/spts_or_iis/http/detected", value:TRUE );
  set_kb_item( name:"microsoft/spts_or_iis/http/" + host + "/" + port + "/detected", value:TRUE );

  # nb: In earlier versions of this VT a CPE like e.g.:
  # > cpe:/a:microsoft:sharepoint_team_services:2007
  # got registered. But as this is most likely wrong these days we are saving the full received
  # version here for now.
  msts_cpe = build_cpe( value:mstsVersion, exp:"^([0-9.]+)", base:msts_base_cpe + ":" );
  if( ! msts_cpe )
    msts_cpe = msts_base_cpe;

  register_product( cpe:msts_cpe, location:install, port:port, service:"www" );

  report = build_detection_report( app:"Microsoft SharePoint Team Services",
                                   version:mstsVersion,
                                   install:install,
                                   cpe:msts_cpe,
                                   concluded:concluded );

  # nb:
  # - According to external sources the WSS are a free light version of the Microsoft SharePoint
  #   Server
  # - WSS 2003 -> Light version of SharePoint Server 2003
  # - WSS 2007 -> Light version of SharePoint Server 2007
  # - After these two versions it seems the light version was dropped
  #   - That's probably the reason why the original author of this detection only included these two
  #     code parts here (no comments had been given unfortunately on the reasoning so this is only a
  #     guess)
  # - See e.g. https://www.it-visions.de/%7B78CF0009-2991-4045-87F3-3D178CBE4ECF%7D.aspx for more
  #   info
  # - In the future we might be able to extract the service pack using the [0-9] pattern (minor version number)
  # - See e.g. https://web.archive.org/web/20100827045016/http://www.microsoft.com/downloads/details.aspx?FamilyId=D51730B5-48FC-4CA2-B454-8DC2CAF93951&displaylang=en#Requirements
  if( eregmatch( pattern:"(6\.0\.2\.[0-9]+)", string:mstsVersion ) ) {

    wssVersion = "2.0";
    set_kb_item( name:"microsoft/windows_sharepoint_services/version", value:wssVersion );
    set_kb_item( name:"microsoft/windows_sharepoint_services/detected", value:TRUE );
    set_kb_item( name:"microsoft/windows_sharepoint_services/http/detected", value:TRUE );

    wss_cpe = build_cpe( value:wssVersion, exp:"^([0-9.]+)", base:wss_base_cpe + ":" );
    if( ! wss_cpe )
      wss_cpe = wss_base_cpe;

    register_product( cpe:wss_cpe, location:install, port:port, service:"www" );

    report += '\n\n';
    report += build_detection_report( app:"Microsoft Windows SharePoint Services (WSS)",
                                      version:wssVersion,
                                      install:install,
                                      concluded:mstsConcluded,
                                      cpe:wss_cpe
                                    );
  }

  if( eregmatch( pattern:"(12\.[0-9.]+)", string:mstsVersion ) ) {

    wssVersion = "3.0";
    set_kb_item( name:"microsoft/windows_sharepoint_services/version", value:wssVersion );
    set_kb_item( name:"microsoft/windows_sharepoint_services/detected", value:TRUE );
    set_kb_item( name:"microsoft/windows_sharepoint_services/http/detected", value:TRUE );

    wss_cpe = build_cpe( value:wssVersion, exp:"^([0-9.]+)", base:wss_base_cpe + ":" );
    if( ! wss_cpe )
      wss_cpe = wss_base_cpe;

    register_product( cpe:wss_cpe, location:install, port:port, service:"www" );

    report += '\n\n';
    report += build_detection_report( app:"Microsoft Windows SharePoint Services (WSS)",
                                      version:wssVersion,
                                      install:install,
                                      concluded:mstsConcluded,
                                      cpe:wss_cpe
                                    );
  }

  if( iisBanner[2] ) {

    # nb:
    # - OS fingerprint using IIS signature
    # - See e.g. https://en.wikipedia.org/wiki/Internet_Information_Services#History
    # - This is only for the reporting below, OS registration itself is done separately already in /
    #   via gb_microsoft_iis_http_detect.nasl
    # - Also no register_product() as this is also done in the IIS detection itself already
    if( iisBanner[2] == "10.0" )
      osVersion = "Windows Server 2022 / Windows Server 2019 / Windows Server 2016 / Windows 10 / Windows 11";

    if( iisBanner[2] == "8.5" )
      osVersion = "Windows Server 2012 R2 / Windows 8.1";

    if( iisBanner[2] == "8.0" )
      osVersion = "Windows Server 2012 / Windows 8";

    if( iisBanner[2] == "7.5" )
      osVersion = "Windows Server 2008 R2 / Windows 7";

    if( iisBanner[2] == "7.0" )
      osVersion = "Windows Server 2008 / Windows Vista";

    if( iisBanner[2] == "6.0" )
      osVersion = "Windows Server 2003 / Windows XP Professional x64";

    if( iisBanner[2] == "5.1" )
      osVersion = "Windows XP Professional";

    if( iisBanner[2] == "5.0" )
      osVersion = "Windows 2000";

    if( iisBanner[2] == "4.0" )
      osVersion = "Windows NT 4.0 Option Pack";

    if( iisBanner[2] == "3.0" )
      osVersion = "Windows NT 4.0 SP2";

     if( iisBanner[2] == "2.0" )
      osVersion = "Windows NT 4.0";

    if( iisBanner[2] == "1.0" )
      osVersion = "Windows NT 3.51";

    extra = " - " + iisBanner[0];
    if( osVersion )
      extra += '\n - Operating System Type: ' + osVersion;
  }

  # nb: If ever required this could be extracted in a dedicated detection...
  if( aspNetVersion[1] ) {

    set_kb_item( name:"microsoft/aspnet/version", value:aspNetVersion[1] );
    set_kb_item( name:"microsoft/aspnet/http/version", value:aspNetVersion[1] );

    extra += '\n - ' + aspNetVersion[0];

    # nb: Only used within the previous if() on purpose to not report "too much"
    if( xPoweredBy[1] ) {

      set_kb_item( name:"microsoft/aspx/enabled", value:TRUE );
      set_kb_item( name:"microsoft/aspx/http/enabled", value:TRUE );

      if( extra )
        extra += '\n';
      extra += " - " + xPoweredBy[0];
    }
  }

  if( strlen( report ) > 0 ) {
    if( extra )
      report += '\n\nExtra information:\n' + extra;

    report += '\n\nConcluded from version/product identification location:\n' + concludedUrl;

    log_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 0 );
