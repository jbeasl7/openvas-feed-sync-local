# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100504");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-02-23 17:05:07 +0100 (Tue, 23 Feb 2010)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2008-7064");
  script_name("Quicksilver Forums Local File Include and Arbitrary File Upload Vulnerabilities");
  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("quicksilver_forums_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("quicksilver/forum/detected", "Host/runs_windows");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");

  script_tag(name:"summary", value:"Quicksilver Forums is prone to a local file-include vulnerability and
  an arbitrary-file-upload vulnerability because the application fails
  to sufficiently sanitize user-supplied input.");

  script_tag(name:"impact", value:"An attacker can exploit these issues to upload arbitrary files onto
  the webserver, execute arbitrary local files within the context of the
  webserver, and obtain sensitive information. By exploiting the arbitrary-file-
  upload and local file-include vulnerabilities at the same time, the
  attacker may be able to execute remote code.");

  script_tag(name:"affected", value:"Quicksilver Forums 1.4.2 is vulnerable, other versions may also be
  affected. Note that these issues affect only versions running on
  Windows platforms.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/32452");
  script_xref(name:"URL", value:"http://pdnsadmin.iguanadons.net/index.php?a=newspost&t=85");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");
include("host_details.inc");
include("version_func.inc");

port = http_get_port(default:80);

if(!version = get_kb_item(string("www/", port, "/quicksilver")))
  exit(0);

if(!matches = eregmatch(string:version, pattern:"^(.+) under (/.*)$"))
  exit(0);

vers = matches[1];

if(vers && "unknown" >!< vers) {
  if(version_is_less_equal(version: vers, test_version: "1.4.2")) {
    security_message(port:port);
    exit(0);
  }
}

exit(0);
