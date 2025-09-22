# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:joomla:joomla";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807368");
  script_version("2023-07-21T05:05:22+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-09-27 10:23:31 +0530 (Tue, 27 Sep 2016)");

  script_name("Joomla! Component Event Booking SQL Injection Vulnerability");

  script_tag(name:"summary", value:"Joomla component event booking is prone to an SQL injection (SQLi) vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request
  and check whether it is able to execute sql query or not.");

  script_tag(name:"insight", value:"The flaw exists due to an insufficient
  validation of user supplied input via 'Date' parameter to 'index.php'
  script.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to inject or manipulate SQL queries in the back-end database,
  allowing for the manipulation or disclosure of arbitrary data.");

  script_tag(name:"affected", value:"Joomla Event Booking Component version 2.10.1");

  script_tag(name:"solution", value:"Update to version 2.10.4.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_active");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/40423");
  script_xref(name:"URL", value:"https://www.joomdonation.com/forum/events-booking-general-discussion/54939-events-booking-2-11-0-released.html");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl");
  script_mandatory_keys("joomla/installed");
  script_require_ports("Services/www", 80);

  script_xref(name:"URL", value:"http://extensions.joomla.org/extension/event-booking");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!http_port = get_app_port(cpe:CPE))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:http_port))
  exit(0);

if(dir == "/")
  dir = "";

url = dir + "/index.php?option=com_eventbooking&view=calendar&layout" +
            "=weekly&date=%27SQL-INJECTION-TEST&Itemid=354#";

if(http_vuln_check(port:http_port, url:url, pattern:"You have an error in your SQL syntax",
                   extra_check:make_list('SQL-INJECTION-TEST', '>1064 - Error: 1064<', 'FROM #__eb_events AS'))) {
  report = http_report_vuln_url(port:http_port, url:url);
  security_message(port:http_port, data:report);
  exit(0);
}

exit(99);
