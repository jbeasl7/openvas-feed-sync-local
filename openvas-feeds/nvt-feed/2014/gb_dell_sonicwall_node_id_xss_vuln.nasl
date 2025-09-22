# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804239");
  script_version("2025-05-14T05:40:11+0000");
  script_tag(name:"last_modification", value:"2025-05-14 05:40:11 +0000 (Wed, 14 May 2025)");
  script_tag(name:"creation_date", value:"2014-02-17 19:09:31 +0530 (Mon, 17 Feb 2014)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2014-0332");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("DELL SonicWALL < 7.2 XSS Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"DELL SonicWALL is prone to a cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The flaw is due to an input passed via the 'node_id' parameter
  to 'sgms/mainPage', which is not properly sanitised before using it.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to steal the
  victim's cookie-based authentication credentials.");

  script_tag(name:"affected", value:"DELL SonicWALL versions 7.0 and 7.1 are known to be
  affected.");

  script_tag(name:"solution", value:"Update to version 7.2 or later.");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/91062");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65498");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/125180");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2014/Feb/108");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");

port = http_get_port(default: 80);

res = http_get_cache(port: port, item: "/sgms/login");

if (">Dell SonicWALL Analyzer Login<" >!< res && ">Dell SonicWALL GMS Login<" >!< res)
  exit(0);

url = '/sgms/mainPage?node_id=aaaaa";><script>alert(document.cookie);</script>';

if (http_vuln_check(port: port, url: url, check_header:TRUE,
                    pattern: "><script>alert\(document\.cookie\);</script>")) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
