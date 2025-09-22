# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:jetspeed";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807648");
  script_cve_id("CVE-2016-0709", "CVE-2016-0710", "CVE-2016-0711", "CVE-2016-0712",
                "CVE-2016-2171");
  script_version("2024-02-19T05:05:57+0000");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-19 05:05:57 +0000 (Mon, 19 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-04-20 18:24:00 +0000 (Wed, 20 Apr 2016)");
  script_tag(name:"creation_date", value:"2016-04-01 13:19:30 +0530 (Fri, 01 Apr 2016)");
  script_name("Apache Jetspeed Multiple Vulnerabilities (Mar 2016)");

  script_tag(name:"summary", value:"Apache Jetspeed is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted HTTP GET request and check
  whether it is possible to read a cookie or not.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An improper validation of file names before writing them to disk in
    'Import/Export' function in the Portal Site Manager.

  - An authorization flaw in jetspeed user manager services.

  - An insufficient validation of 'user' and 'role' parameters in
    jetspeed User Manager service.

  - An error in the URI path directory after '/portal'.

  - Some errors in the functionality to add a link, page, or folder.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to obtain potentially sensitive information, and allows to upload
  arbitrary files, also causes sql injection.");

  script_tag(name:"affected", value:"Apache Jetspeed version 2.2.0 to 2.2.2
  and 2.3.0

  - ---
  NOTE: The unsupported Jetspeed 2.1.x versions may be also affected.

  - ---");

  script_tag(name:"solution", value:"Upgrade to Apache Jetspeed version 2.3.1");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_xref(name:"URL", value:"https://portals.apache.org/jetspeed-2/security-reports.html");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_apache_jetspeed_detect.nasl");
  script_mandatory_keys("Jetspeed/Installed");
  script_require_ports("Services/www", 8080);
  script_xref(name:"URL", value:"https://portals.apache.org/jetspeed-2/download.html");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!jetPort = get_app_port(cpe:CPE)){
  jetPort = 8080;
}

if(!dir = get_app_location(cpe:CPE, port:jetPort)){
  exit(0);
}

url = dir + '/foo%22onmouseover%3d%22alert%28document.cookie%29?URL=foo/bar';

if(http_vuln_check(port:jetPort, url:url, check_header:TRUE,
   pattern:"alert\(document\.cookie\)",
   extra_check:make_list("Jetspeed","Username", "Password")))
{
  report = http_report_vuln_url( port:jetPort, url:url );
  security_message(port:jetPort, data:report);
  exit(0);
}
