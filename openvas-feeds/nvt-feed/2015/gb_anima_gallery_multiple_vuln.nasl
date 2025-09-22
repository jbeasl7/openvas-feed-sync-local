# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805581");
  script_version("2023-12-13T05:05:23+0000");
  script_cve_id("CVE-2015-4415");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2015-06-08 13:52:36 +0530 (Mon, 08 Jun 2015)");
  script_name("Anima Gallery Multiple Vulnerabilities");

  script_tag(name:"summary", value:"Anima Gallery is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request
  and check whether it is able to read cookie or not.");

  script_tag(name:"insight", value:"Multiple flaws exist as

  - Input passed via 'id' GET parameter is not properly sanitised before being
  returned to the user.

  - Application does not restrict access to sensitive files.

  - Application does not validate data uploaded by the user.

  - Input passed via 'theme' and 'lang' cookie parameter is not properly
  sanitised before being returned to the user.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to upload an arbitrary file and execute arbitrary code, gain access
  to potentially sensitive information and execute arbitrary script code in a
  user's browser within the trust relationship between their browser and the
  server.");

  script_tag(name:"affected", value:"Anima Gallery version 2.6");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/132150");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/75061");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/535705/100/0/threaded");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

aniPort = http_get_port(default:80);

if(!http_can_host_php(port:aniPort)){
  exit(0);
}

foreach dir (make_list_unique("/", "/AnimaGallery", "/anima", http_cgi_dirs(port:aniPort)))
{

  if( dir == "/" ) dir = "";

  rcvRes = http_get_cache(item:string(dir,"/index.php"), port:aniPort);

  if(rcvRes =~ "Powered By.*>Anima Gallery<")
  {
    url = dir + "/?id=</title><script>prompt(document.cookie)</script>&lo" +
                "ad=dir&refresh=1";

    if(http_vuln_check(port:aniPort, url:url, check_header:TRUE,
                       pattern:"title><script>prompt\(document\.cookie\)</script>",
                       extra_check:">Anima Gallery<"))
    {
      report = http_report_vuln_url( port:aniPort, url:url );
      security_message(port:aniPort, data:report);
      exit(0);
    }
  }
}

exit(99);
