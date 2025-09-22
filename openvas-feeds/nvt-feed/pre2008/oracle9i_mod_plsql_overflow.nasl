# SPDX-FileCopyrightText: 2002 Matt Moore
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:oracle:application_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10840");
  script_version("2025-03-20T05:38:32+0000");
  script_tag(name:"last_modification", value:"2025-03-20 05:38:32 +0000 (Thu, 20 Mar 2025)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2001-1216");
  script_name("Oracle 9iAS mod_plsql Buffer Overflow");
  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_copyright("Copyright (C) 2002 Matt Moore");
  script_family("Web application abuses");
  script_dependencies("gb_oracle_app_server_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("oracle/application_server/detected");

  script_xref(name:"URL", value:"http://www.nextgenss.com/advisories/plsql.txt");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/3726");
  script_xref(name:"URL", value:"http://otn.oracle.com/deploy/security/pdf/modplsql.pdf");

  script_tag(name:"solution", value:"Oracle have released a patch for this vulnerability.");

  script_tag(name:"summary", value:"Oracle 9i Application Server uses Apache as it's web
  server. There is a buffer overflow in the mod_plsql module
  which allows an attacker to run arbitrary code.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!get_app_location(cpe:CPE, port:port, nofork:TRUE))
  exit(0);

if(http_is_dead(port:port))
  exit(0);

soc = http_open_socket(port);
if(!soc)
  exit(0);

# Send 215 chars at the end of the URL
buf = http_get(item:string("/XXX/XXXXXXXX/XXXXXXX/XXXX/", crap(215)), port:port);
send(socket:soc, data:buf);
recv = http_recv(socket:soc);
close(soc);

if(!recv)
  exit(0);

soc = http_open_socket(port);
if(!soc)
  exit(0);

buf = http_get(item:string("/pls/portal30/admin_/help/", crap(215)), port:port);
send(socket:soc, data:buf);
unbreakable = http_recv(socket:soc);
http_close_socket(soc);

if(!unbreakable) {
  security_message(port:port);
  exit(0);
}

exit(99);
