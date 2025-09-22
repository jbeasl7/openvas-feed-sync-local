# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108182");
  script_version("2025-03-28T15:41:52+0000");
  script_tag(name:"last_modification", value:"2025-03-28 15:41:52 +0000 (Fri, 28 Mar 2025)");
  script_tag(name:"creation_date", value:"2017-06-13 12:57:33 +0200 (Tue, 13 Jun 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Mautic Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl",
                      "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.mautic.org/");

  script_tag(name:"summary", value:"HTTP based detection of Mautic.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("cpe.inc");
include("host_details.inc");

port = http_get_port(default:443);

if(!http_can_host_php(port:port))
  exit(0);

detection_patterns = make_list(

  # <title>Mautic</title>
  # <title> Mautic    </title>
  "<title>\s*Mautic\s*</title>",

  # var mauticBasePath
  # var mauticBaseUrl
  # var mauticAjaxUrl
  # var mauticAjaxCsrf
  # var mauticImagesPath
  # var mauticAssetPrefix
  # var mauticContent
  # var mauticEnv
  # var mauticLang
  "var mautic(Base(Path|Url)|Ajax(Url|Csrf)|ImagesPath|AssetPrefix|Content|Env|Lang)",

  # Copyright 2024 Mautic. All Rights Reserved.
  # Copyright 2024 Mautic. Todos os direitos reservados.            </div>
  "Mautic\. All Rights Reserved\.",

  # X-Mautic-Version: 2.15.1
  "X-Mautic-Version\s*:\s*[0-9.]+",

  #    <h2 class="panel-title">
  #        Mautic Installation - Environment Check    </h2>
  "Mautic Installation - Environment Check"
);

login_urls = make_list(

  # nb: Newer versions with "index.php less" URLs
  "/s/login",

  # nb: Fallback for older versions
  "/index.php/s/login",

  # nb: If not installed yet
  "/index.php/installer",
  "/installer"
);

foreach dir(make_list_unique("/", "/mautic", http_cgi_dirs(port:port))) {

  install = dir;
  if(dir == "/")
    dir = "";

  foreach login_url(login_urls) {

    # nb: For each URL we're resetting the counter
    found = 0;

    concluded = ""; # nb: To make openvas-nasl-lint happy...

    url = dir + login_url;
    login_res = http_get_cache(port:port, item:url);

    foreach pattern(detection_patterns) {

      concl = eregmatch(string:login_res, pattern:pattern, icase:TRUE);
      if(concl[0]) {
        found++;
        if(concluded)
          concluded += '\n';
        concluded += "  " + concl[0];
      }
    }

    # nb: Have seen at least one system with a "<title>Site is offline</title>" title but it was
    # possible to detect the system from the favicon in that case
    if(found == 1) {
      favicon_url = dir + "/media/images/favicon.ico";
      req = http_get(port:port, item:favicon_url);
      res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
      if(!isnull(res)) {
        md5 = hexstr(MD5(res));
        if(md5 == "2f5268cde78789978184e8f9c9e2b76e") {
          conclUrl = "  " + http_report_vuln_url(port:port, url:favicon_url, url_only:TRUE);
          concluded += '\n  Favicon md5 hash: ' + md5;
          found++;
        }
      }
    }

    if(found >= 2)
      break; # nb: Assuming that the product is only installed once on the target for now
  }

  if(found >= 2)
    break; # nb: Same as above
}

if(found >= 2) {

  if(conclUrl)
    conclUrl += '\n';
  conclUrl += "  " + http_report_vuln_url(port:port, url:url, url_only:TRUE);

  version = "unknown";

  # nb: This is protected by a .htaccess but still try to gather the version if unprotected
  url = dir + "/app/release_metadata.json";
  res = http_get_cache(port:port, item:url);

  # "version": "4.4.10"
  # "version": "4.4.8"
  # "version": "4.4.12"
  # "version": "4.4.3"
  # "version": "4.4.4"
  # "version": "5.1.0"
  # "version": "5.0.4"
  # "version": "5.1.1"
  # "version": "4.3.1"
  vers = eregmatch(string:res, pattern:'"version"\\s*:\\s*"([0-9.]+)(-beta([0-9])?)?"', icase:FALSE);
  if(vers) {
    version = vers[1];
    conclUrl += '\n  ' + http_report_vuln_url(port:port, url:url, url_only:TRUE);
    concluded += '\n  ' + vers[0];
  }

  if(version == "unknown") {

    # nb: Works only on older versions, e.g.:
    url = dir + "/app/version.txt";
    res = http_get_cache(item:url, port:port);

    # 2.16.3
    # 2.15.3
    # 2.16.5
    vers = egrep(pattern:"^([0-9.]{3,})$", string:res);

    if(res =~ "^HTTP/1\.[01] 200" && vers) {
      version = chomp(vers);
      conclUrl += '\n  ' + http_report_vuln_url(port:port, url:url, url_only:TRUE);
      concluded += '\n  ' + version;
    }
  }

  if(version == "unknown") {

    # e.g.:
    # X-Mautic-Version: 2.15.1
    #
    # nb: No need to add this to the "concluded" reporting as it is already included previously
    vers = eregmatch(pattern:"[Xx]-[Mm]autic-[Vv]ersion\s*:\s*([0-9.]+)", string:login_res, icase:FALSE);
    if(vers[1])
      version = vers[1];
  }

  set_kb_item(name:"mautic/detected", value:TRUE);
  set_kb_item(name:"mautic/http/detected", value:TRUE);

  cpe = build_cpe(value:version, exp:"^([0-9.]+)(-beta([0-9])?)?", base:"cpe:/a:mautic:mautic:");
  if(!cpe)
    cpe = "cpe:/a:mautic:mautic";

  register_product(cpe:cpe, location:install, port:port, service:"www");

  log_message(data:build_detection_report(app:"Mautic",
                                          version:version,
                                          install:install,
                                          cpe:cpe,
                                          concludedUrl:conclUrl,
                                          concluded:concluded),
              port:port);
}

exit(0);
