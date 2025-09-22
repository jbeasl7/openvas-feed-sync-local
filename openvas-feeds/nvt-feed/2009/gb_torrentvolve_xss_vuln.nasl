# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900577");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2009-06-26 07:55:21 +0200 (Fri, 26 Jun 2009)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-2101");
  script_name("TorrentVolve archive.php XSS Vulnerability");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/8931");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/51088");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("secpod_torrentvolve_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("torrentvolve/detected");

  script_tag(name:"affected", value:"TorrentVolve 1.4 and prior.");

  script_tag(name:"insight", value:"The flaw occurs because archive.php does not sanitise the data
  passed into 'deleteTorrent' parameter before being returned to the user.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"TorrentVolve is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to delete arbitrary
  files on the affected system if register_globals is enabled.");

  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");
include("version_func.inc");

tvPort = http_get_port(default:80);

tvVer = get_kb_item("www/" + tvPort + "/TorrentVolve");
tvVer = eregmatch(pattern:"^(.+) under (/.*)$", string:tvVer);
if(tvVer[1] == NULL){
  exit(0);
}

if(version_is_less_equal(version:tvVer[1], test_version:"1.4")){
  security_message(tvPort);
}
