# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mongodb:mongodb";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805730");
  script_version("2023-07-14T16:09:27+0000");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:27 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-07-24 11:51:27 +0530 (Fri, 24 Jul 2015)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"Workaround");

  script_name("MongoDB 2.4.x, 2.6.x Information Disclosure Vulnerability - Active Check");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Databases");
  script_dependencies("gb_mongodb_webadmin_detect.nasl");
  script_require_ports("Services/mongodb", 28017);
  script_mandatory_keys("mongodb/webadmin/port");

  script_tag(name:"summary", value:"MongoDB is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The flaw exists as mongodb does not have a 'bind_ip 127.0.0.1'
  option set in the mongodb.conf.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to gain
  access to potentially sensitive information.");

  script_tag(name:"affected", value:"MongoDB version 2.4.x and 2.6.x.");

  script_tag(name:"solution", value:"Change the mongodb configuration file to not listen on all
  interfaces.");

  script_xref(name:"URL", value:"https://blog.shodan.io/its-the-data-stupid");
  script_xref(name:"URL", value:"https://jira.mongodb.org/browse/SERVER-4216");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!get_app_location(cpe: CPE, port: port, nofork: TRUE))
  exit(0);

url = "/";

if (http_vuln_check(port: port, url: url, check_header: TRUE, pattern:">mongod",
                    extra_check: make_list("BOOST_LIB_VERSION", "databases", "db version"), usecache: TRUE)) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
