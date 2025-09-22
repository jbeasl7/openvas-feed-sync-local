# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:nicholas_berry:candid";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807583");
  script_version("2023-07-20T05:05:17+0000");
  script_cve_id("CVE-2010-4978", "CVE-2010-4979");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-05-09 16:11:35 +0530 (Mon, 09 May 2016)");
  script_tag(name:"qod_type", value:"remote_analysis");
  script_name("CANDID 'view.php' SQL Injection and Cross Site Scripting Vulnerabilities");

  script_tag(name:"summary", value:"CANDID is prone to sql injection and cross site scripting vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request
  and check whether it is able to execute sql query or not.");

  script_tag(name:"insight", value:"Multiple flaws exist due to insufficient
  validation of user supplied input via 'image_id' parameter in
  'image/view.php' script.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to steal cookie-based authentication credentials, compromise the
  application, access or modify data, or exploit latent vulnerabilities in the
  underlying database.");

  script_tag(name:"affected", value:"CANDID version 2.50 and probably earlier
  versions.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
  Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/41216");
  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/91251");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_candid_remote_detect.nasl");
  script_mandatory_keys("CANDID/Installed");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if(!candidPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!dir = get_app_location(cpe:CPE, port:candidPort)){
  exit(0);
}

if(dir == "/") dir = "";
url = dir + "/image/view.php?image_id='SQL-INJECTION-TEST";

if(http_vuln_check(port:candidPort, url:url, check_header:TRUE,
                   pattern:"You have an error in your SQL syntax",
                   extra_check:"SQL-INJECTION-TEST"))
{
  report = http_report_vuln_url(port:candidPort, url:url);
  security_message(port:candidPort, data:report);
  exit(0);
}
