# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809038");
  script_version("2026-06-12T07:09:59+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2026-06-12 07:09:59 +0000 (Fri, 12 Jun 2026)");
  script_tag(name:"creation_date", value:"2016-09-08 11:15:03 +0530 (Thu, 08 Sep 2016)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("ClipBucket Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl",
                      "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of ClipBucket.");

  script_xref(name:"URL", value:"https://oxygenz.fr/en/clipbucketv5/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 443);

if (!http_can_host_php(port: port))
  exit(0);

foreach dir (make_list_unique("/", "/clipbucket", "/ClipBucket", http_cgi_dirs(port: port))) {
  install = dir;

  if (dir == "/")
    dir = "";

  url = dir + "/admin_area/login.php";

  res = http_get_cache(port: port, item: url);

  if (("ClipBucket Copyright" >< res || res =~ "clipbucket\.(min.)?js") &&
      (">Sign in with your Clipbucket" >< res || "Username" >< res) &&
      (res =~ "<title>Admin Login - ClipBucket.*</title>" || "Arslan Hassan" >< res ||
       "summernote()" >< res)) {
    version = "unknown";
    conclUrl = "  " + http_report_vuln_url(port: port, url: url, url_only: TRUE);

    url = dir + "/";

    res = http_get_cache(port: port, item: url);

    vers = eregmatch(pattern: "ClipBucket(V5)? version ([0-9.]+)", string: res);
    if (!isnull(vers[2])) {
      version = vers[2];
      conclUrl += '\n  ' + http_report_vuln_url(port: port, url: url, url_only: TRUE);
    }

    set_kb_item(name: "clipbucket/detected", value: TRUE);
    set_kb_item(name: "clipbucket/http/detected", value: TRUE);

    cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:oxygenz:clipbucket:");
    if(!cpe)
      cpe = "cpe:/a:oxygenz:clipbucket";

    register_product(cpe: cpe, location: install, port: port, service: "www");

    log_message(data: build_detection_report(app: "ClipBucket", version: version, install: install, cpe: cpe,
                                             concluded: vers[0], concludedUrl: conclUrl),
                port: port);
    exit(0);
  }
}

exit(0);
