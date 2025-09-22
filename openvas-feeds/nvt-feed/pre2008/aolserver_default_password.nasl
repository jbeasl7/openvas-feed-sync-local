# SPDX-FileCopyrightText: 2001 SecuriTeam
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:aol:aolserver";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10753");
  script_version("2025-03-11T05:38:16+0000");
  script_cve_id("CVE-1999-0507", "CVE-1999-0508");
  script_tag(name:"last_modification", value:"2025-03-11 05:38:16 +0000 (Tue, 11 Mar 2025)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("AOLserver Default Password (HTTP)");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2001 SecuriTeam");
  script_family("Default Accounts");
  script_dependencies("gb_aol_server_detect.nasl", "gb_default_credentials_options.nasl");
  script_mandatory_keys("aol/server/detected");
  script_require_ports("Services/www", 8000);
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_tag(name:"summary", value:"The remote web server is running AOL web server (AOLserver) with
  the default username and password set.");

  script_tag(name:"vuldetect", value:"Tries to login via HTTP using a known default credentials.");

  script_tag(name:"impact", value:"An attacker may use this to gain control of the remote web
  server.");

  script_tag(name:"solution", value:"Change the default username and password on your web server.");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

if(get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

include("host_details.inc");
include("http_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!get_app_location(port:port, cpe:CPE, nofork:TRUE))
  exit(0);

# nb:
# - http_report_vuln_url() used below might fork on multiple hostnames and should be always before
#   the first http_keepalive_send_recv call
# - For simplicity we're just calling http_host_name() directly here as it will also fork
http_host_name(port:port);

url = "/nstelemetry.adp";
req = string("GET ", url, " HTTP/1.0\r\nAuthorization: Basic bnNhZG1pbjp4\r\n\r\n");
res = http_send_recv(port:port, data:req);

if(ereg(string:res, pattern:"^HTTP/1\.[01] 200") && "AOLserver Telemetry" >< res) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
