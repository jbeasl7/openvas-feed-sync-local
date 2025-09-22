# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140348");
  script_version("2025-06-16T05:41:07+0000");
  script_tag(name:"last_modification", value:"2025-06-16 05:41:07 +0000 (Mon, 16 Jun 2025)");
  script_tag(name:"creation_date", value:"2017-09-05 08:44:27 +0700 (Tue, 05 Sep 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("NetApp Data ONTAP Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of NetApp Data ONTAP.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80, 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

banner = http_get_remote_headers(port: port);

if (egrep(pattern: "(NetApp|Data ONTAP)/", string: banner)) {
  detected = TRUE;
} else {

  # nb: The page has the following versions exposed but its currently not absolutely clear if these are also matching the Data ONTAP version.
  # <meta sm_build_version="9.1" />
  # <meta sm_build_version="9.0RC2" />
  # <meta sm_build_version="8.3.1">
  # <meta sm_build_version="8.3.2RC1">

  buf = http_get_cache(item: "/sysmgr/SysMgr.html", port: port);
  if (buf && "<meta sm_build_version" >< buf && "sysmgr/sysmgr.nocache.js" >< buf)
    detected = TRUE;
}

if (detected) {
  set_kb_item(name: "netapp_data_ontap/detected", value: TRUE);
  set_kb_item(name: "netapp_data_ontap/http/detected", value: TRUE);
  set_kb_item(name: "netapp_data_ontap/http/port", value: port);

  vers = eregmatch(pattern: "Server\s*:\s*(NetApp|Data ONTAP)//?([0-9P.]+)", string: banner);
  if (!isnull(vers[2])) {
    version = vers[2];
    set_kb_item(name: "netapp_data_ontap/http/" + port + "/version", value: version);
    set_kb_item(name: "netapp_data_ontap/http/" + port + "/concluded", value: vers[0]);
  } else {
    set_kb_item(name: "netapp_data_ontap/http/" + port + "/concluded", value: "NetApp OnCommand System Manager Interface");
  }
}

exit(0);
