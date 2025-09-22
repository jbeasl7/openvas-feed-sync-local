# SPDX-FileCopyrightText: 2008 Ferdy Riphagen
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:embedthis:goahead";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.2000099");
  script_version("2024-12-20T15:39:18+0000");
  script_tag(name:"last_modification", value:"2024-12-20 15:39:18 +0000 (Fri, 20 Dec 2024)");
  script_tag(name:"creation_date", value:"2008-08-22 16:09:14 +0200 (Fri, 22 Aug 2008)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2002-1603");
  script_xref(name:"OSVDB", value:"13295");
  script_name("Embedthis GoAhead < 2.1.8 Script Source Code Disclosure Vulnerability - Active Check");
  script_category(ACT_ATTACK); # nb: The used requests might be already seen as an attack...
  script_family("Web Servers");
  script_copyright("Copyright (C) 2008 Ferdy Riphagen");
  script_dependencies("gb_embedthis_goahead_http_detect.nasl");
  script_mandatory_keys("embedthis/goahead/http/detected");
  script_require_ports("Services/www", 80);

  script_xref(name:"URL", value:"http://aluigi.altervista.org/adv/goahead-adv3.txt");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/9239");
  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/975041");

  script_tag(name:"summary", value:"Embedthis GoAhead is prone to a script source code disclosure
  vulnerability.");

  script_tag(name:"vuldetect", value:"Sends multiple crafted HTTP GET requests and checks the
  responses.");

  script_tag(name:"insight", value:"The version installed is vulnerable to a script source code
  disclosure, by adding extra characters to the URL. Possible characters are %00, %5C, %2F.");

  script_tag(name:"affected", value:"Embedthis GoAhead versions prior to 2.1.8.");

  script_tag(name:"solution", value:"Update to version 2.1.8 or later.");

  script_tag(name:"qod_type", value:"remote_probe");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");

function GetFileExt(file) {
  local_var file, ret;
  ret = split(file, sep:".");
  return ret;
}

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!get_app_location(cpe:CPE, port:port, nofork:TRUE))
  exit(0);

banner = http_get_remote_headers(port:port);

host = http_host_name(port:port);

# Possible default file which still could be available.
file[0] = "/treeapp.asp";

# Below options could possible create false-positives.
file[1] = "/default.asp";

if (banner =~ "^HTTP/1\.[01] 30." && banner =~ "Location\s*:") {
  redirect = egrep(pattern:"^[Ll]ocation\s*:", string:banner);
  rfile = ereg_replace(pattern:"Location\s*:\s*https?:\/\/+[^/]+", string:redirect, replace:"", icase:TRUE);

  # See if the file is really asp.
  ret = GetFileExt(file:rfile);
  if (!isnull(ret)) {
    if (ereg(pattern:"asp", string:ret[1], icase:TRUE)) {
      file[2] = chomp(rfile);
    }
  }
}

for (n = 0; file[n]; n++) {

  url = file[n] + "%5C";
  req = string("GET ", url, " HTTP/1.1", "\r\n",
               "Host: ", host, "\r\n\r\n");
  res = http_send_recv(port:port, data:req); # nb: Server doesn't support keepalives.

  if ('<% write(HTTP_AUTHORIZATION); %>' >< res ||
     ('<%' >< res && ('%>' >< res))) {
    report = http_report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);
