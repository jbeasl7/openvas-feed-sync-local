# SPDX-FileCopyrightText: 2001 INTRANODE
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:internet_information_services";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10732");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_version("2023-10-10T05:05:41+0000");
  script_tag(name:"last_modification", value:"2023-10-10 05:05:41 +0000 (Tue, 10 Oct 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/2736");
  script_cve_id("CVE-2001-0337");
  script_name("Microsoft IIS 5.0 WebDav Memory Leakage Vulnerability - Active Check");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2001 INTRANODE");
  script_family("Denial of Service");
  script_dependencies("gb_microsoft_iis_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("microsoft/iis/http/detected");

  script_tag(name:"solution", value:"Download Service Pack 2/hotfixes from Microsoft.");

  script_tag(name:"summary", value:"The WebDav extensions (httpext.dll) for Internet Information
  Server 5.0 contains a flaw that may allow a malicious user to consume all available memory on
  the target server by sending many requests using the LOCK method associated to a non
  existing filename.

  This concern not only IIS but the entire system since the flaw can
  potentially exhausts all system memory available.");

  script_tag(name:"affected", value:"Vulnerable systems: IIS 5.0 (httpext.dll versions prior to 0.9.3940.21)

  Immune systems: IIS 5 SP2 (httpext.dll version 0.9.3940.21)");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!get_app_location(cpe:CPE, port:port, nofork:TRUE))
  exit(0);

host = http_host_name(port:port);

quote = raw_string(0x22);
poison = string("PROPFIND / HTTP/1.1\r\n",
                "Host: ", host, "\r\n",
                "Content-Type: text/xml\r\n",
                "Content-Length: 110\r\n\r\n",
                "<?xml version=", quote, "1.0", quote, "?>\r\n",
                "<a:propfind xmlns:a=", quote, "DAV:", quote, ">\r\n",
                " <a:prop>\r\n",
                "  <a:displayname:/>\r\n",
                " </a:prop>\r\n",
                "</a:propfind>\r\n");

soc = http_open_socket(port);
if(!soc) exit(0);

send(socket:soc, data:poison);
code = recv_line(socket:soc, length:1024);
http_close_socket(soc);

if(!code || code !~ "^HTTP/1\.[01] 207")
  exit(0);

security_message(port:port);
exit(0);
