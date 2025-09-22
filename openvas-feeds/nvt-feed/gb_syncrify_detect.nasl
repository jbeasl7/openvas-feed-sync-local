# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100819");
  script_version("2025-03-04T05:38:25+0000");
  script_tag(name:"last_modification", value:"2025-03-04 05:38:25 +0000 (Tue, 04 Mar 2025)");
  script_tag(name:"creation_date", value:"2010-09-22 16:24:51 +0200 (Wed, 22 Sep 2010)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Syncrify Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("Service detection");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 5800);
  script_mandatory_keys("Apache-Coyote/banner");

  script_tag(name:"summary", value:"HTTP based detection of Syncrify.");

  script_xref(name:"URL", value:"http://web.synametrics.com/Syncrify.htm");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default:5800);

banner = http_get_remote_headers(port:port);
if(!banner || "Server: Apache-Coyote" >!< banner)
  exit(0);

url = string("/app?operation=about");
req = http_get(item:url, port:port);
buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
if(!buf)
  exit(0);

# nb: The second "Synametrics Technologies" is missing a compare operator. Please re-check this when
# touching this detection (TODO task: VTD-2216).
if("Syncrify" >< buf && "Synametrics Technologies" && "Fast incremental backup" >< buf) {

  install = "/";

  vers = string("unknown");
  version = eregmatch(string:buf, pattern:"Version: ([0-9.]+) - build ([0-9]+)", icase:TRUE);

  if(!isnull(version[1])) {
    vers = chomp(version[1]);
    if(!isnull(version[2])) {
      vers = vers + "." + version[2]; # ver string: Version: 2.1 build 420 -> version in kb 2.1.420
    }
  }

  set_kb_item(name:"www/" + port + "/syncrify", value:string(vers, " under ", install));
  set_kb_item(name:"syncrify/app/detected", value:TRUE); # nb: There is a "server" Detection-VT as well.

  info = string("Syncrify Version '");
  info += string(vers);
  info += string("' was detected on the remote host in the following directory(s):\n\n");
  info += string(install, "\n");

  log_message(port:port, data:info);
  exit(0);
}

exit(0);
