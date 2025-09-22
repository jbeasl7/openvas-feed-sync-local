# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106125");
  script_version("2025-03-19T05:38:35+0000");
  script_tag(name:"last_modification", value:"2025-03-19 05:38:35 +0000 (Wed, 19 Mar 2025)");
  script_tag(name:"creation_date", value:"2016-07-11 12:33:22 +0700 (Mon, 11 Jul 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Micro Focus Service Manager Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Micro Focus Service Manager (Formerly HP
  Service Manager).");

  script_xref(name:"URL", value:"https://docs.microfocus.com/doc/Service_Manager/9.80/Home");


  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 443);

foreach dir (make_list_unique("/", "/sm", "/smsso", "/sm92", "/sm7", "/sc", "/hpsm", "/webtier", "/sm-webtier", "/smwebtier", http_cgi_dirs(port: port))) {
  install = dir;
  if (dir == "/")
    dir = "";

  url = dir + "/index.do";
  res = http_get_cache(port: port, item: url);

  if (res =~ 'Location: (https?://[^/]+)?/' + dir + '/ess\\.do\r\n') {
    url = dir + "/ess.do";
    res = http_get_cache(port: port, item: url);
  }

  if (("HPLogoSolidBlue.ico" >< res || 'id="xHtoken"' >< res) &&
      res =~ 'id="old\\.password"\\s+name="old\\.password"/>') {
    version = "unknown";
    conclUrl = http_report_vuln_url(port: port, url: url, url_only: TRUE);

    # <script type="text/javascript" src="/<redacted>/js/9.52.0026/debug/login/login.js
    # <script type="text/javascript" src="/smsso/js/9.40.2001/login/login.js"></script>
    # <script type="text/javascript" src="/cwc/js/9.41.8003/login-util.js">/**/</script>
    #
    # As something like this has been seen as well:
    # src="/sm/login/cwc/js/87195799/login-util.js">
    # the version extraction regex was made more strict to require a version starting with at least
    # one number followed by a dot.
    vers = eregmatch(pattern: '<script type="text/javascript"\\s+src="/([a-zA-Z0-9]+/)*([0-9]+\\.[0-9.]{2,})/[a-zA-Z/]*login\\.js',
                     string: res);
    if (!isnull(vers[2]))
      version = vers[2];
    else {
      # <link rel="stylesheet" type="text/css" href="/sm92/css/9.33.3000/login.css">
      # <link rel="stylesheet" type="text/css" href="/smsso/css/9.40.2001/login.css"/>
      vers = eregmatch(pattern: '(href|src)="/([a-zA-Z0-9]+/)*([0-9]+\\.[0-9.]{2,})/login[^.]*\\.(css|js)">', string: res);
      if (!isnull(vers[3]))
        version = vers[3];
      else {
        # <link rel="shortcut icon" href="/sm/images/HPLogoSolidBlue.ico?v=9.60.0025" />
        # <link rel="shortcut icon" href="/smwebtier/images/<redactednumber>/HPLogoSolidBlue.ico?v=9.72.0026" />
        # <link rel="shortcut icon" href="/sm/images/<redactednumber>/HPLogoSolidBlue.ico?v=9.64.0004" />
        vers = eregmatch(pattern: "\.ico\?v=([0-9]+\.[0-9.]{2,})", string: res);
        if (!isnull(vers[1]))
          version = vers[1];
      }
    }

    # nb: script_mandatory_keys for e.g. gb_apache_struts_CVE_2017_5638.nasl
    set_kb_item(name: "www/action_jsp_do", value: TRUE);

    set_kb_item(name: "microfocus/service_manager/detected", value: TRUE);
    set_kb_item(name: "microfocus/service_manager/http/detected", value: TRUE);

    cpe1 = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:microfocus:service_manager:");
    cpe2 = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:hp:service_manager:");
    if (!cpe1) {
      cpe1 = "cpe:/a:microfocus:service_manager";
      cpe2 = "cpe:/a:hp:service_manager";
    }

    register_product(cpe: cpe1, location: install, port: port, service: "www");
    register_product(cpe: cpe2, location: install, port: port, service: "www");

    log_message(data: build_detection_report(app: "Micro Focus Service Manager", version: version,
                                             install: install, cpe: cpe1, concluded: vers[0],
                                             concludedUrl: conclUrl),
                port: port);

    exit(0);
  }
}

exit(0);
