# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800438");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-01-22 09:23:45 +0100 (Fri, 22 Jan 2010)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-4626");
  script_name("phpNagios 'conf[lang]' Parameter Local File Inclusion Vulnerability");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/9611");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/53119");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/2615");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_phpnagios_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("phpnagios/detected");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to obtain sensitive
  information or execute arbitrary code on the vulnerable web server.");

  script_tag(name:"affected", value:"phpNagios version 1.2.0 and prior.");

  script_tag(name:"insight", value:"The flaw is due to error in 'menu.php' and is not properly sanitising
  user supplied input data via 'conf[lang]' parameter.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"phpNagios is prone to local file include Vulnerabilities.");

  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");
include("version_func.inc");

pnPort = http_get_port(default:80);

pnVer = get_kb_item("www/" + pnPort + "/phpNagios");

pnVer = eregmatch(pattern:"^(.+) under (/.*)$", string:pnVer);
if(!isnull(pnVer[1]))
{
  # phpNagios version 1.2.0 (3.0)
  if(version_is_less_equal(version:pnVer[1], test_version:"3.0")){
    security_message(pnPort);
  }
}

