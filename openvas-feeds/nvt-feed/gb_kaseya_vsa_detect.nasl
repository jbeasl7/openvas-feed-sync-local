# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106738");
  script_version("2025-01-31T05:37:27+0000");
  script_tag(name:"last_modification", value:"2025-01-31 05:37:27 +0000 (Fri, 31 Jan 2025)");
  script_tag(name:"creation_date", value:"2017-04-10 14:46:29 +0200 (Mon, 10 Apr 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Kaseya VSA Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of Kaseya VSA.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "global_settings.nasl",
                      "gb_microsoft_iis_http_detect.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.kaseya.com/products/vsa");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("os_func.inc");
include("port_service_func.inc");
include("misc_func.inc");

port = http_get_port(default: 443);
if( ! http_can_host_asp( port:port ) )
  exit( 0 );

host = http_host_name(dont_add_port: TRUE);

# nb: Some need a referer to get the version back
header = make_array("Referer", "https://" + host + "/");
url = "/vsapres/web20/core/login.aspx";
req = http_get_req(port: port, url: url, add_headers: header);
res = http_keepalive_send_recv(port: port, data: req);

if ("logoforLogin.gif" >< res && "/vsapres/js/kaseya/web/bootstrap.js" >< res && "Kaseya" >< res) {
  version = "unknown";
  install = "/";

  # <li id="loginSystemStatusControl_SystemVersionItem">
  #      System Version
  #<br />
  #     <span>9.1.0.0</span>
  #
  # nb: "System Version" could be translated:
  #
  #    <li id="loginSystemStatusControl_SystemVersionItem">
  #        Versione sistema
  #        <br />
  #        <span>9.3.0.4</span>
  #    </li>
  vers = eregmatch(pattern: "SystemVersionItem.*<span>([0-9.]+)</span>", string: res);
  if (!isnull(vers[1])) {
    version = vers[1];
    concUrl = http_report_vuln_url(port: port, url: url, url_only: TRUE);
  }

  # nb: Patchlevel can be higher than the system version
  #
  #    <li id="loginSystemStatusControl_PatchLevelItem">
  #        Patch Level
  #          <br />
  #        <span>None</span>
  #    </li>
  patchlevel = eregmatch(pattern: "PatchLevelItem[^<]+<br />[^<]+<span>([0-9.]+)</span>", string: res);
  if (!isnull(patchlevel[1])) {
    set_kb_item(name: "kaseya_vsa/patchlevel", value: patchlevel[1]);
    extra = "Patch Level:  " + patchlevel[1];
  }

  set_kb_item(name: "kaseya/vsa/detected", value: TRUE);
  set_kb_item(name: "kaseya/vsa/http/detected", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:kaseya:virtual_system_administrator:");
  if (!cpe)
    cpe = "cpe:/a:kaseya:virtual_system_administrator";

  os_register_and_report(os: "Microsoft Windows", cpe: "cpe:/o:microsoft:windows",
                         desc: "Kaseya VSA Detection (HTTP)", runs_key: "windows");

  register_product(cpe: cpe, location: install, port: port, service: "www");

  log_message(data: build_detection_report(app: "Kaseya VSA", version: version, install: install, cpe: cpe,
                                           concluded: vers[0], concludedUrl: concUrl, extra: extra),
              port: port);
  exit(0);
}

exit(0);
