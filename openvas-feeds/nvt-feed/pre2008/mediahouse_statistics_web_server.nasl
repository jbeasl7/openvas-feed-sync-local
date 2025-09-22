# SPDX-FileCopyrightText: 2001 Noam Rathaus
# SPDX-FileCopyrightText: 2001 SecuriTeam
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

# Could also cover BugtraqID:734, CVE:CVE-1999-0931

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10748");
  script_version("2025-03-10T05:35:40+0000");
  script_tag(name:"last_modification", value:"2025-03-10 05:35:40 +0000 (Mon, 10 Mar 2025)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2000-0776");
  script_name("Mediahouse Statistics Web Server Multiple Vulnerabilities (2001)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2001 SecuriTeam & Copyright (C) 2001 Noam Rathaus");
  script_family("Web Servers");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("Statistics_Server/banner");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/1568");

  script_tag(name:"summary", value:"Mediahouse Statistics web server is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Mediahouse Statistics web server suffers from a security
  vulnerability that enables attackers to gain sensitive information on the current logged events on
  the public web server (the server being monitored by MediaHouse).

  This information includes: who is on (currently surfing users), the user's actions, customer's IP
  addresses, referrer URLs, hidden directories, web server usernames and passwords, and more.

  Some versions of the product also suffer from a flaw that allows attackers to overflow an internal
  buffer causing it to execute arbitrary code.");

  script_tag(name:"solution", value:"Block the web server's port number on your Firewall, and update
  to the latest version if necessary.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");

port = http_get_port(default:80);
buf = http_get_remote_headers(port:port);
if(!buf)
  exit(0);

if(!egrep(pattern:"^[Ss]erver\s*:\s*Statistics Server", string:buf))
  exit(0);

buf = strstr(buf, "Location: ");
buf = buf - "Location: ";
subbuf = strstr(buf, string("\n"));
buf = buf - subbuf;
buf = buf - raw_string(0x0D);

# nb: Should be always before the first http_open_socket() call
req = http_get(item:buf, port:port);

if(!soc = http_open_socket(port))
  exit(0);

send(socket:soc, data:req);
buf = http_recv(socket:soc);
http_close_socket(soc);

if(!buf || "Statistics Server " >!< buf)
  exit(0);

buf = strstr(buf, "<TITLE>Statistics Server ");
buf = buf - "<TITLE>Statistics Server ";
subbuf = strstr(buf, "</TITLE>");
buf = buf - subbuf;
buf = buf - "</TITLE>";
version = buf;

buf = "Remote host is running Statistics Server version: ";
buf = buf + version;
if(ereg(pattern:"(([0-4]\.[0-9].*)|5\.0[0-2])", string:version)) {
  report = string("According to its version number, the remote MediaHouse\n",
                  "Statistics Server is vulnerable to a buffer overflow that\n",
                  "allows anyone to execute arbitrary code as root.\n\n",
                  "Solution: Upgrade to version 5.03 or newer");
  security_message(data:report, port:port);
} else {
  security_message(port:port);
}

exit(0);
