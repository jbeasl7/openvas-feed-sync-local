# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100193");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-05-10 17:01:14 +0200 (Sun, 10 May 2009)");
  script_cve_id("CVE-2009-1911");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("TinyWebGallery/QuiXplorer Local File Include Vulnerability");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_dependencies("TinyWebGallery_detect.nasl", "gb_quixplorer_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("tinywebgallery_or_quixplorer/detected");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");

  script_tag(name:"summary", value:"TinyWebGallery and QuiXplorer are prone to a local file-include vulnerability
  because it fails to properly sanitize user-supplied input.");

  script_tag(name:"impact", value:"An attacker can exploit this vulnerability to view files and execute
  local scripts in the context of the webserver process. This may aid in further attacks.");

  script_tag(name:"affected", value:"TinyWebGallery 1.7.6 and prior versions are vulnerable.

  QuiXplorer 2.3.2 and prior versions are vulnerable.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34892");
  script_xref(name:"URL", value:"http://www.tinywebgallery.com/forum/viewtopic.php?t=1653");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");
include("version_func.inc");

port = http_get_port(default:80);
version = get_kb_item(string("www/", port, "/TinyWebGallery"));
if(version) {
  matches = eregmatch(string:version, pattern:"^(.+) under (/.*)$");
  vers = matches[1];
  if(vers && "unknown" >!< vers) {
    if(version_is_less_equal(version: vers, test_version: "1.7.6")) {
     security_message(port:port, data:"The target host was found to be vulnerable.");
     exit(0);
    }
  }
}

quixplorerVer = get_kb_item(string("www/", port, "/QuiXplorer"));
if(quixplorerVer) {
  qxplorerVer = eregmatch(string:quixplorerVer, pattern:"^(.+) under (/.*)$");
  if(qxplorerVer && version_is_less_equal(version: qxplorerVer[1], test_version:"2.3.2")){
    security_message(port:port, data:"The target host was found to be vulnerable.");
    exit(0);
  }
}

exit(99);
