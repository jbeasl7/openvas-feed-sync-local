# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801075");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-12-09 07:52:52 +0100 (Wed, 09 Dec 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-4204", "CVE-2009-4205");
  script_name("Flashlight Free Edition SQL Injection and Directory Traversal Vulnerability");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/8856");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/50906");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_flashlight_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("flashlight/free/detected");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to view, add,
  modify or delete information in the back end database or include arbitrary files
  from local and remote resources to compromise a vulnerable server.");

  script_tag(name:"affected", value:"Flashlight Free version 1.0 on all running platform.");

  script_tag(name:"insight", value:"Flaws are due to:

  - An error in 'read.php' which is not properly sanitizing user supplied input
  before being used in SQL queries via 'id' parameter.

  - An error in 'admin.php' which is not properly sanitizing user supplied input
  before being used via a .. (dot dot) in the action 'parameter' which causes
  directory traversal attacks in the application context.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"Flashlight Free Edition is prone to SQL Injection and Directory Traversal Vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");
include("version_func.inc");

fPort = http_get_port(default:80);

fVer = get_kb_item("www/" + fPort + "/Flashlight/Free");
if(!fVer)
  exit(0);

fVer = eregmatch(pattern:"^(.+) under (/.*)$", string:fVer);
if(fVer[1] != NULL)
{
  if(version_is_equal(version:fVer[1], test_version:"1.0")){
    security_message(fPort);
  }
}
