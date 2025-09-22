# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807563");
  script_version("2024-06-17T08:31:37+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-06-17 08:31:37 +0000 (Mon, 17 Jun 2024)");
  script_tag(name:"creation_date", value:"2016-04-27 10:47:16 +0530 (Wed, 27 Apr 2016)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Dell EMC OpenManage Server Administrator (OMSA) Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 1311);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Dell EMC OpenManage Server
  Administrator (OMSA).");

  script_xref(name:"URL", value:"https://www.dell.com/support/kbdoc/en-us/000132087/support-for-dell-emc-openmanage-server-administrator-omsa");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 1311);

foreach dir (make_list("/", "/servlet")) {
  install = dir;
  if (dir == "/")
    dir = "";

  url = dir + "/Login?omacmd=getlogin&page=Login&managedws=true";

  req = http_get(port: port, item: url);
  res = http_keepalive_send_recv(port: port, data: req);

  if (res =~ '(application"|nowrap"?)>Server Administrator' && ">Login" >< res &&
      ("dell" >< res || '"omsa"' >< res)) {
    version = "unknown";
    concUrl = http_report_vuln_url(port: port, url: url, url_only: TRUE);

    url =  dir + "/UDataArea?plugin=com.dell.oma.webplugins.AboutWebPlugin";
    req = http_get(item: url, port: port);
    res = http_keepalive_send_recv(port: port, data: req);

    # <br>Version 5.2.0<br>Copyright (C) Dell Inc. 1995-2007. All rights reserved.<br>
    # <br>Version 6.3.0<br>Copyright (C) Dell Inc. 1995-2010 All rights reserved.<br>
    # <td class="item"><span class="bold"></span></td><td class="desc25">Version 7.0.0</td>
    # <td class="item"><span class="bold">Dell OpenManage Server Administrator</span></td><td class="desc25">Version 7.3.2</td>
    # <td class="item"><span class="bold">Dell OpenManage Server Administrator</span></td><td class="desc25">Version 7.4.0</td>
    # <td class="item"><span class="bold">Dell OpenManage Server Administrator</span></td><td class="desc25">Version 8.5.0</td>
    # <td class="item"><span class="bold">Dell OpenManage Server Administrator</span></td><td class="desc25">Version 11.0.0.0</td>
    #
    # But also:
    # <td class="item"><span class="bold">Dell OpenManage Systems Management Software (64-Bit)</span></td><td class="desc25">Version 7.3.0</td>
    # which had later the following so this seems to be also a OMSA:
    # <td class="item"><span>Server Administrator Core files</span></td><td class="desc">Version 7.3.0 (350)</td>
    #
    # and similar:
    # <td class="item"><span class="bold">Dell OpenManage Systems Management Software (64-Bit)</span></td><td class="desc25">Version 8.1.0.1</td>
    # which had later the following so this seems to be also a OMSA:
    # <td class="item"><span>Server Administrator Core files</span></td><td class="desc">Version 8.1.0.1 (1612)</td>
    #
    vers = eregmatch(pattern: ">Version\s+([0-9.]+)" , string: res);
    if (!isnull(vers[1])) {
      version = vers[1];
      concUrl += '\n' + http_report_vuln_url(port: port, url: url, url_only: TRUE);
    }

    set_kb_item(name: "dell/openmanage_server_administrator/detected", value:TRUE);
    set_kb_item(name: "dell/openmanage_server_administrator/http/detected", value: TRUE);

    cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:dell:emc_openmanage_server_administrator:");
    if (!cpe)
      cpe= "cpe:/a:dell:emc_openmanage_server_administrator";

    register_product(cpe: cpe, location: install, port: port, service: "www");

    log_message(data: build_detection_report(app: "Dell EMC OpenManage Server Administrator (OMSA)", version: version,
                                             install: install,cpe: cpe, concluded: vers[0],
                                             concludedUrl: concUrl),
                port: port);
    exit(0);
  }
}

exit(0);
