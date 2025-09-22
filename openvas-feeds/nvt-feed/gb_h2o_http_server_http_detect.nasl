# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806993");
  script_version("2024-06-11T05:05:40+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-06-11 05:05:40 +0000 (Tue, 11 Jun 2024)");
  script_tag(name:"creation_date", value:"2016-01-25 13:12:26 +0530 (Mon, 25 Jan 2016)");
  script_name("H2O HTTP Server Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of the H2O HTTP server.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 443);
  script_mandatory_keys("h2o/banner");

  script_xref(name:"URL", value:"https://h2o.examp1e.net/");

  exit(0);
}

include("cpe.inc");
include("http_func.inc");
include("port_service_func.inc");
include("host_details.inc");

port = http_get_port(default:443);

banner = http_get_remote_headers(port:port);
if(!banner)
  exit(0);

if(!concl = egrep(string:banner, pattern:"^[Ss]erver\s*:\s*h2o", icase:FALSE))
  exit(0);

concl = chomp(concl);
version = "unknown";
install = "/";

# nb:
# - To tell http_can_host_php from http_func.inc that the service is supporting this
# - Product can definitely host PHP scripts (via some PHP-fpm/FastCGI integration)
# - TBD: replace_kb_item(name:"www/" + port + "/can_host_asp", value:"yes"); ?
replace_kb_item(name:"www/" + port + "/can_host_php", value:"yes");

vers = eregmatch(pattern:"[Ss]erver\s*:\s*h2o/([0-9a-zA-Z.-]+)", string:banner);
if(!isnull(vers[1])) {
  version = vers[1];
  concl = vers[0];
}

set_kb_item(name:"h2o/detected", value:TRUE);
set_kb_item(name:"h2o/http/detected", value:TRUE);

cpe = build_cpe(value:tolower(version), exp:"^([0-9a-zA-Z.-]+)", base:"cpe:/a:h2o_project:h2o:");
if(!cpe)
  cpe = "cpe:/a:h2o_project:h2o";

register_product(cpe:cpe, location:install, port:port, service:"www");

log_message(data:build_detection_report(app:"H2O HTTP Server", version:version, install:install, cpe:cpe,
                                        concluded:concl),
            port:port);
exit(0);
