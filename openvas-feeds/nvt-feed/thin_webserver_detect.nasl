# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100300");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2023-07-28T16:09:08+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:08 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-10-11 19:51:15 +0200 (Sun, 11 Oct 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Thin Webserver Detection");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("Service detection");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 3000);
  script_mandatory_keys("thin/banner");

  script_tag(name:"summary", value:"This host is running Thin, a Ruby web server.");

  script_xref(name:"URL", value:"http://code.macournoyer.com/thin/");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");

port = http_get_port(default:3000);
banner = http_get_remote_headers(port:port);
if(!banner || "Server: thin" >!< banner)exit(0);

vers = string("unknown");
version = eregmatch(string: banner, pattern: "Server: thin ([0-9.]+)",icase:TRUE);
if ( !isnull(version[1]) ) {
  vers = chomp(version[1]);
}

set_kb_item(name: string("www/", port, "/thin"), value: string(vers));

info = string("Thin Version '");
info += string(vers);
info += string("' was detected on the remote host\n");
log_message(port:port,data:info);

exit(0);
