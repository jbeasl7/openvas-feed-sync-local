# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.144110");
  script_version("2024-07-16T05:05:43+0000");
  script_tag(name:"last_modification", value:"2024-07-16 05:05:43 +0000 (Tue, 16 Jul 2024)");
  script_tag(name:"creation_date", value:"2020-06-16 02:30:35 +0000 (Tue, 16 Jun 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("ZNC Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of ZNC.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 6667);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 6667);

res = http_get_cache(port: port, item: "/");

if (concl = eregmatch(string: res, pattern: '(Server\\s*:\\s*ZNC|ZNC - Web Frontend)[^\r\n]+', icase: TRUE)) {
  version = "unknown";
  concluded = chomp(concl[0]);

  # nb:
  # - To tell http_can_host_asp and http_can_host_php from http_func.inc that the service is
  #   NOT supporting these
  # - There is a slight chance that a system is configured in a way that it acts as a proxy and
  #   exposes the product on the known endpoints and an additional web server supporting e.g. PHP
  #   on a different endpoint. Thus the following is only set if the port are the default ones
  #   6667, 6668 and 6697 (see e.g. gb_znc_http_detect.nasl as well)
  # - The "Server: ZNC" is already included in the two http_func.inc functions, this is only for
  #   non-default systems like mentioned previously
  if (port == 6667 || port == 6668 || port == 6697) {
    replace_kb_item(name: "www/" + port + "/can_host_php", value: "no");
    replace_kb_item(name: "www/" + port + "/can_host_asp", value: "no");
  }

  set_kb_item(name: "znc/detected", value: TRUE);
  set_kb_item(name: "znc/http/detected", value: TRUE);
  set_kb_item(name: "znc/http/port", value: port);
  set_kb_item(name: "znc/http/" + port + "/detected", value: TRUE);

  # nb: Note that the version itself can be hidden via a setting of ZNC.
  #
  # Server: ZNC - http://znc.in
  # Server: ZNC 1.7.5 - https://znc.in
  # Server: ZNC 1.9.x-git-9-84d8375a - https://znc.in
  # Server: ZNC 1.7.0+deb0+trusty1 - https://znc.in
  # Server: ZNC - 1.6.0 - http://znc.in
  # Server: ZNC 1.8.2+deb3.1 - https://znc.in
  # Server: ZNC 1.8.2+deb3.1+deb12u1 - https://znc.in
  vers = eregmatch(pattern: "[Ss]erver\s*:\s*ZNC( \-)? ([0-9.]+)[^ ]* - http", string: res);
  if (!isnull(vers[2])) {
    version = vers[2];
    concluded = vers[0];
  }

  # or if the server banner is hidden behind e.g. a Proxy the related HTML code for the version:
  #
  # <div id="tag"><p>ZNC - 1.6.0 - <a href="http://znc.in">http://znc.in</a></p></div>
  # <div id="banner"><p>ZNC 1.7.5 - <a href="https://znc.in">https://znc.in</a></p></div>
  # <div id="tag"><p>ZNC 1.7.2+deb3 - <a href="https://znc.in">https://znc.in</a></p></div>
  if (version == "unknown") {
    vers = eregmatch(pattern: ">ZNC( \-)? ([0-9.]+)[^ ]* - <", string: res);
    if (!isnull(vers[2])) {
      version = vers[2];
      concluded = vers[0];
    }
  }

  set_kb_item(name: "znc/http/" + port + "/concluded", value: concluded);
  set_kb_item(name: "znc/http/" + port + "/version", value: version);
}

exit(0);
