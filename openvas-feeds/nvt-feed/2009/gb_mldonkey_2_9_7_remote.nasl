# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mldonkey:mldonkey";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100057");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2009-03-17 18:51:21 +0100 (Tue, 17 Mar 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2009-0753");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MLDonkey <= 2.9.7 Arbitrary File Download Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Peer-To-Peer File Sharing");
  script_dependencies("gb_mldonkey_consolidation.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 4080);
  script_mandatory_keys("mldonkey/http/detected");

  script_tag(name:"summary", value:"MLDonkey is prone to a vulnerability that lets attackers
  download arbitrary files. The issue occurs because the application fails to sufficiently sanitize
  user-supplied input.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"impact", value:"Exploiting this issue will allow an attacker to view arbitrary
  files within the context of the application. Information harvested may aid in launching further
  attacks.");

  script_tag(name:"affected", value:"MLDonkey version 2.9.7 and probably prior.");

  script_tag(name:"solution", value:"Fixes are available.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/33865");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("traversal_func.inc");
include("os_func.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!get_app_location(cpe: CPE, port: port, nofork: TRUE))
  exit(0);

files = traversal_files();

foreach pattern (keys(files)) {
  file = files[pattern];

  url = "//" + file;

  if (http_vuln_check(port: port, url: url, pattern: pattern)) {
    report = http_report_vuln_url(port: port, url: url);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(0); # nb: Server allows connections only from localhost by default so no exit(99) as it might be still vulnerable
