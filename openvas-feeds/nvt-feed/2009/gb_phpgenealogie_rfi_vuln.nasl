# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:phpgenealogy:phpgenealogy";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801008");
  script_version("2023-07-21T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-10-08 08:22:29 +0200 (Thu, 08 Oct 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-3541");
  script_name("PHPGenealogie 2.0 'CoupleDB.php' RFI Vulnerability");
  script_category(ACT_MIXED_ATTACK);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_phpgenealogie_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("phpgenealogie/http/detected");

  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/9155");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/51728");

  script_tag(name:"summary", value:"PHPGenealogie is prone to a remote file inclusion (RFI)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Depending on the 'safe_checks' setting of the scan
  configuration:

  - Setting 'yes': Checks if a vulnerable version is present on the target host

  - Setting 'no': Sends a crafted HTTP GET request and checks the response");

  script_tag(name:"insight", value:"The flaw is due to error in 'DataDirectory' parameter in
  'CoupleDB.php' which is not properly verified before being used to include files.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary
  code on the vulnerable Web server.");

  script_tag(name:"affected", value:"PHPGenealogie version 2.0 is known to be affected. Other
  versions might be affected as well.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:FALSE))
  exit(0);

vers = infos["version"];
dir = infos["location"];

loc = dir;
if(dir == "/")
  dir = "";

if(!safe_checks()) {

  url = dir + "/CoupleDB.php?Parametre=0&DataDirectory=xyz/VT-RemoteFileInclusion.txt";
  req = http_get(item:url, port:port);
  res = http_keepalive_send_recv(port:port, data:req);
  if("xyz/VT-RemoteFileInclusion.txt" >< res) {
    report = http_report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
    exit(0);
  }
}

if(vers && version_is_less_equal(version:vers, test_version:"2.0")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"None", install_path:loc);
  security_message(port:port, data:report);
  exit(0);
}

exit(0);
