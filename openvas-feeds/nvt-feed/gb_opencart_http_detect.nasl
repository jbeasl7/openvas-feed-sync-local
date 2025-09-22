# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100178");
  script_version("2024-07-12T15:38:44+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-07-12 15:38:44 +0000 (Fri, 12 Jul 2024)");
  script_tag(name:"creation_date", value:"2009-05-02 19:46:33 +0200 (Sat, 02 May 2009)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("OpenCart Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of OpenCart.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl",
                      "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.opencart.com/");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("cpe.inc");
include("host_details.inc");

port = http_get_port(default:80);
if(!http_can_host_php(port:port))
  exit(0);

detection_patterns = make_list(

  # <p>Powered By <a href="https://www.opencart.com">OpenCart</a><br/> Your Store &copy; 2024</p>
  # <p>Powered By <a href="https://www.opencart.com">OpenCart</a><br/> Storename &copy; 2024</p>
  # div id="powered">Powered By <a href="http://www.opencart.com">OpenCart</a><br />  &copy; 2024</div>
  "[Pp]owered [Bb]y <a [^>]+>[Oo]pen[Cc]art",

  "<title>.* \([Pp]owered [Bb]y [Oo]pen[Cc]art\)</title>",

  # Set-Cookie: OCSESSID=<redacted>; path=/
  # Set-Cookie: language=en-gb; expires=Sat, 10-Aug-2024 12:...
  #
  # nb: This is not used as separate strings as having both should be only counted "as one" because
  # they are a little bit too weak as "standalone" detection pattern.
  "^[Ss]et-[Cc]ookie\s*:\s*(language|OCSESSID)=.+",

  # <!-- Google Marketing Tools Opencart - https://devmanextensions.com -->
  "<!-- Google Marketing Tools [Oo]pen[Cc]art[^>]+>",

  #     <!--
  # OpenCart is open source software and you are free to remove the powered by OpenCart if you want, but its generally accepted practise to make a small donation.
  # Please donate via PayPal to donate@opencart.com
  # //-->
  "OpenCart is open source software and you are free to remove the powered by OpenCart if you want",

  # <img src="http://<redacted>/image/catalog/opencart-logo.png" title="Your Store" alt="Your Store" class="img-fluid"/></a>
  "<img src=[^>]+opencart-logo\.png"
);

foreach dir(make_list_unique("/shop", "/store", "/opencart", "/upload", http_cgi_dirs(port:port))) {

  install = dir;
  if(dir == "/")
    dir = "";

  url = dir + "/index.php";
  buf = http_get_cache(item:url, port:port);
  if(!buf || buf !~ "^HTTP/1\.[01] 200")
    continue;

  found = 0;
  adminurl_found = FALSE;
  concluded = ""; # nb: To make openvas-nasl-lint happy...

  foreach pattern(detection_patterns) {

    concl = egrep(string:buf, pattern:pattern, icase:FALSE);
    if(concl) {

      # nb: Minor formatting change for the reporting. The egrep() above might include multiple
      # lines so we need to split them first.
      split_lines = split(concl, keep:FALSE);
      foreach split_line(split_lines) {

        split_line = ereg_replace(string:split_line, pattern:"^(\s+)", replace:"");

        # nb: Only include these result once as this would make the reporting too big otherwise...
        if("Google Marketing Tools" >< split_line && "Google Marketing Tools" >< concluded)
          continue;

        if("OCSESSID=" >< split_line && "OCSESSID=" >< concluded)
          continue;

        if("OpenCart is open source software" >< split_line && "OpenCart is open source software" >< concluded)
          continue;

        if(concluded)
          concluded += '\n';

        concluded += "  " + split_line;
      }

      found++;
    }
  }

  # nb: Just another fallback if the system is highly customized
  if(found == 1) {

    url2 = dir + "/admin/index.php";
    buf = http_get_cache(item:url2, port:port);

    # <a href="https://<redacted>/admin/index.php?route=common/login" class="navbar-brand d-none d-lg-block"><img src="view/image/logo.png" alt="OpenCart" title="OpenCart" /></a>
    # <div id="header-logo" class="navbar-header"><a href="https://3<redacted>/admin/index.php?route=common/login" class="navbar-brand"><img src="view/image/logo.png" alt="OpenCart" title="OpenCart" /></a></div>
    # <footer id="footer"><a href="https://www.opencart.com">OpenCart</a> &copy; 2009-2024 All Rights Reserved.<br/></footer></div>
    # <div id="footer"><a href="http://www.opencart.com">OpenCart</a> &copy; 2009-2024 All Rights Reserved.<br />Version 1.5.6</div>
    # <footer id="footer"><a href="http://www.opencart.com">OpenCart</a> &copy; 2009-2024 All Rights Reserved.<br/></footer></div>
    if(concl = eregmatch(string:buf, pattern:'(alt="OpenCart"|title="OpenCart"|>OpenCart<|https?://www\\.opencart\\.com)', icase:FALSE)) {
      found++;
      concluded += '\n  ' + concl[0];
      # nb: Just to not add the same URL a second time later
      adminurl_found = TRUE;
      concUrl = "  " + http_report_vuln_url(port:port, url:url2, url_only:TRUE);
    }
  }

  if(found > 1) {

    version = "unknown";

    if(concUrl)
      concUrl += '\n';
    concUrl += "  " + http_report_vuln_url(port:port, url:url, url_only:TRUE);

    url = dir + "/admin/index.php";
    res = http_get_cache(item:url, port:port);

    # <div id="footer"><a href="http://<redacted>">redacted</a> &copy; 2009-2024 All Rights Reserved.<br />Version 1.5.5.1.2</div>
    # <div id="footer"><a href="http://www.opencart.com">OpenCart</a> &copy; 2009-2024 All Rights Reserved.<br />Version 1.5.5.1</div>
    # <div id="footer"><a href="http://www.opencart.com">OpenCart</a> &copy; 2009-2024 All Rights Reserved.<br />Version 1.5.6</div>
    # <div id="footer"><a href="http://www.opencart.com">OpenCart</a> &copy; 2009-2024 All Rights Reserved.<br />Version 1.5.6.4</div>
    vers = eregmatch(pattern:">Version ([0-9.]+)<", string:res);
    if(!isnull(vers[1])) {
      version = vers[1];
      concluded += '\n  ' + vers[0];
      if(!adminurl_found)
        concUrl += '\n  ' + http_report_vuln_url(port:port, url:url, url_only:TRUE);
    } else {
      url = dir + "/CHANGELOG.md";
      res = http_get_cache(port: port, item: url);

      # ## [v3.0.1.2] (Release date: 07.07.2017)
      # ## [v4.0.2.2] (Release date: 18.04.2023)
      vers = eregmatch(pattern:"## \[v([0-9.]+)", string:res);
      if (!isnull(vers[1])) {
        version = vers[1];
        concluded += '\n  ' + vers[0];
        concUrl += '\n  ' + http_report_vuln_url(port:port, url:url, url_only:TRUE);
      }
    }

    set_kb_item(name:"opencart/detected",value:TRUE);
    set_kb_item(name:"opencart/http/detected",value:TRUE);

    cpe = build_cpe(value:version, exp:"^([0-9.]+)", base:"cpe:/a:opencart:opencart:");
    if(!cpe)
      cpe = "cpe:/a:opencart:opencart";

    register_product(cpe:cpe, location:install, port:port, service:"www");

    log_message(data:build_detection_report(app:"OpenCart",
                                            version:version,
                                            install:install,
                                            cpe:cpe,
                                            concluded:concluded,
                                            concludedUrl:concUrl),
                port:port);

    # nb: Most likely only installed a single time on the target and also prevents that we're
    # reporting "too much" based on the cookies.
    exit(0);
  }
}

exit(0);
