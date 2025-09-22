# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:vpet:vpet_engine";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808174");
  script_version("2023-10-12T05:05:32+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-10-12 05:05:32 +0000 (Thu, 12 Oct 2023)");
  script_tag(name:"creation_date", value:"2016-06-27 12:52:04 +0530 (Mon, 27 Jun 2016)");
  script_name("VPet Engine SQL Injection and Backdoor Account Vulnerabilities");

  script_tag(name:"summary", value:"vPet Engine is prone to sql injection and backdoor account vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted HTTP GET request and check
  whether it is able to execute sql query or not.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An improper validation of user supplied input to 'game' parameter.

  - A backdoor accounts 'admin' and password as 'admin'.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to inject or manipulate SQL queries in the back-end database,
  allowing for the manipulation or disclosure of arbitrary data and also
  can gain administrative access of the system.");

  script_tag(name:"affected", value:"vPet Engine Version 2.1");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"qod_type", value:"remote_active");

  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/137626/vpetengine-sqlbackdoor.txt");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_vpet_engine_detect.nasl");
  script_mandatory_keys("vPet/Engine/Installed");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!vpet_Port = get_app_port(cpe:CPE))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:vpet_Port))
  exit(0);

if(dir == "/")
  dir = "";

url = dir + "/index.php?game=VT-SQL-INJECTION-TEST'";
if(http_vuln_check(port:vpet_Port, url:url, check_header:TRUE,
                   pattern:"supplied argument is not a valid MySQL",
                   extra_check: make_list("VT-SQL-INJECTION-TEST", "vPet Engine")))
{
  report = http_report_vuln_url( port:vpet_Port, url:url );
  security_message(port:vpet_Port, data:report);
  exit(0);
}

exit(99);
