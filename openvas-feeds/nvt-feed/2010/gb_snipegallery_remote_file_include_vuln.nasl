# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801218");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-06-09 08:34:53 +0200 (Wed, 09 Jun 2010)");
  script_cve_id("CVE-2010-2126");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Snipe Gallery 'cfg_admin_path' Multiple Remote File Include Vulnerabilities");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/58806");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/40279");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/1004-exploits/snipegallery-rfi.txt");
  script_xref(name:"URL", value:"http://eidelweiss-advisories.blogspot.com/2010/04/snipegallery-315-multiple-remote-file.html");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_snipegallery_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("snipegallery/detected");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary
  PHP code in the context of an affected site.");

  script_tag(name:"affected", value:"Snipe Gallery Version 3.1.4 and 3.1.5.");

  script_tag(name:"insight", value:"The flaw is caused by improper validation of user-supplied
  input via the 'cfg_admin_path' parameter to index.php, view.php, image.php,
  search.php, admin/index.php, admin/gallery/index.php, admin/gallery/view.php,
  admin/gallery/gallery.php, admin/gallery/image.php, and admin/gallery/crop.php
  that allow the attackers to execute arbitrary PHP code on the web server.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"Snipe Gallery is prone to multiple remote file include vulnerabilities.");

  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");
include("version_func.inc");

port = http_get_port(default:80);

ver = get_kb_item("www/" + port + "/snipegallery");
snipeVer = eregmatch(pattern:"^(.+) under (/.*)$", string:ver);

if(snipeVer[1])
{
   if(version_is_equal(version:snipeVer[1], test_version:"3.1.4") ||
      version_is_equal(version:snipeVer[1], test_version:"3.1.5") ){
     security_message(port);
   }
}
