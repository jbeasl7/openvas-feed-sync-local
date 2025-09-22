# SPDX-FileCopyrightText: 2002 Matt Moore
# SPDX-FileCopyrightText: New NASL code since 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11037");
  script_version("2025-01-22T05:38:11+0000");
  script_tag(name:"last_modification", value:"2025-01-22 05:38:11 +0000 (Wed, 22 Jan 2025)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2002-1855", "CVE-2002-1856", "CVE-2002-1857", "CVE-2002-1858",
                "CVE-2002-1859", "CVE-2002-1860", "CVE-2002-1861", "CVE-2016-0793");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-05-10 01:29:00 +0000 (Thu, 10 May 2018)");
  script_name("'/WEB-INF./' Information Disclosure Vulnerability (HTTP)");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2002 Matt Moore / 2021 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.westpoint.ltd.uk/advisories/wp-02-0002.txt");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/5119");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/136323/Wildfly-Filter-Restriction-Bypass-Information-Disclosure.html");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/39573");
  script_xref(name:"URL", value:"https://security.netapp.com/advisory/ntap-20180215-0001/");
  script_xref(name:"URL", value:"https://support.hpe.com/hpesc/public/docDisplay?docLocale=en_US&docId=emr_na-hpesbhf03784en_us");
  script_xref(name:"URL", value:"https://kb.vmware.com/s/article/2041178");
  script_xref(name:"URL", value:"https://securiteam.com/windowsntfocus/5op050a7pe/");

  script_tag(name:"summary", value:"Various application or web servers / products are prone to an
  information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"affected", value:"The following products are known to be affected:

  - Sybase EA Server 4.0

  - OC4J - Oracle Containers for J2EE

  - Orion 1.5.3

  - JRun 3.0, 3.1 and JRun 4 - Macromedia / Allaire JRun

  - HPAS 8.0 - Hewlett Packard App Server

  - Pramati 3.0 - Pramati App Server

  - Jo - Jo Webserver

  - WildFly (formerly JBoss Application Server) before 10.0.0.Final

  - HPE B-Series SAN Network Advisor Software Running WildFly (formerly JBoss Application Server)

  - VMware vCenter Server 5.1.x

  Other products might be affected as well.");

  script_tag(name:"insight", value:"The servlet specification prohibits servlet containers from
  serving resources in the '/WEB-INF' and '/META-INF' directories of a web application archive
  directly to clients.

  This means that URLs like:

  http://example.com/WEB-INF/web.xml

  will return an error message, rather than the contents of the deployment descriptor.

  However, some application or web servers / products are prone to a vulnerability that exposes this
  information if the client requests a URL like this instead:

  http://example.com/WEB-INF./web.xml

  http://example.com/web-inf./web.xml

  (note the trailing dot ('.') after 'WEB-INF').");

  script_tag(name:"impact", value:"Based on the information provided in this file an attacker might
  be able to gather additional info and / or sensitive data about the application / the application
  / web server.");

  script_tag(name:"solution", value:"The following vendor fixes are known:

  - Update to EAServer 4.1 (also fixed in maintenance release for 3.6.1).

  - Update to OC4J / 9iAS 9.0.2 or later.

  - Update to Orion 1.5.3 or later.

  - Cumulative Patch available for JRun 3.0, 3.1 / 4.0.

  - Update to HPAS 8.0 Maintenance Pack 8 (MP8) or later.

  - Update to Pramati 3.0 Service Pack 1 or later.

  - Update to Jo Webserver 1.0b7 or later.

  - Update WildFly to version 10.0.0.Final or later.

  For other products please contact the vendor for more information on possible fixes.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

base_pattern  = "^\s*<(web-app( .+|>$)|servlet(-mapping)?>$)";
extra_pattern = "^\s*</(web-app|servlet(-mapping)?)>$";

port = http_get_port( default:8080 );

foreach dir( make_list_unique( "/", "/h2console", http_cgi_dirs( port:port ) ) ) {

  if( dir == "/" )
    dir = "";

  url = dir + "/WEB-INF/web.xml";
  res = http_get_cache( item:url, port:port );

  # nb: Avoid excessive reporting if the file is directly accessible (already checked by
  # 2018/gb_sensitive_file_disclosures_http.nasl and 2021/gb_web-inf_plain_info_disclosure.nasl).
  if( res &&
      egrep( string:res, pattern:base_pattern, icase:FALSE ) &&
      egrep( string:res, pattern:extra_pattern, icase:FALSE ) )
    continue;

  url = dir + "/WEB-INF./web.xml";

  req = http_get( item:url, port:port );
  res = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );

  if( res &&
      egrep( string:res, pattern:base_pattern, icase:FALSE ) &&
      egrep( string:res, pattern:extra_pattern, icase:FALSE ) ) {
    report  = http_report_vuln_url( port:port, url:url );
    report += '\nResponse (truncated):\n\n' + substr( res, 0, 1500 );
    security_message( port:port, data:report );
    exit( 0 );
  }

  # We want to check the lowercase variant as well (from CVE-2016-0793).
  url = str_replace( string:url, find:"/WEB-INF./web.xml", replace:"/web-inf./web.xml" );

  req = http_get( item:url, port:port );
  res = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );
  if( ! res )
    continue;

  if( egrep( string:res, pattern:base_pattern, icase:FALSE ) &&
      egrep( string:res, pattern:extra_pattern, icase:FALSE ) ) {
    report  = http_report_vuln_url( port:port, url:url );
    report += '\nResponse (truncated):\n\n' + substr( res, 0, 1500 );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
