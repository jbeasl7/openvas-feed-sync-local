# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800323");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-05-18 09:37:31 +0200 (Mon, 18 May 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-1486");
  script_name("Flatchat Directory Traversal Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/34904");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34734");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/8549");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_flatchat_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("flatchat/detected");

  script_tag(name:"impact", value:"Successful attacks can cause inclusion or execution of arbitrary
  local files in the context of the webserver process via directory traversal
  attacks and URL-encoded NULL-bytes.");

  script_tag(name:"affected", value:"Flatchat version 3.0 and prior.");

  script_tag(name:"insight", value:"Improper handling of user supplied input into the  pmscript.php
  file via ..(dot dot) in 'with' parameter, can lead to directory traversal.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"Flatchat is prone to a directory traversal vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");
include("version_func.inc");

flatchatPort = http_get_port(default:80);

fcVer = get_kb_item("www/" + flatchatPort + "/Flatchat");
fcVer = eregmatch(pattern:"^(.+) under (/.*)$", string:fcVer);

if(fcVer[1] != NULL)
{
  if(version_is_less_equal(version:fcVer[1], test_version:"3.0")){
    security_message(flatchatPort);
  }
}
