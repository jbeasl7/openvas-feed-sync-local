# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:western_digital:sharespace";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812364");
  script_version("2025-03-24T05:38:38+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-03-24 05:38:38 +0000 (Mon, 24 Mar 2025)");
  script_tag(name:"creation_date", value:"2017-12-26 20:19:48 +0530 (Tue, 26 Dec 2017)");
  script_name("Western Digital ShareSpace <= 2.3.02 WEB GUI Information Disclosure Vulnerability - Active Check");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wd_sharespace_web_detect.nasl");
  script_mandatory_keys("WD/ShareSpace/detected");
  script_require_ports("Services/www", 80);

  script_xref(name:"URL", value:"https://seclists.org/fulldisclosure/2012/Jun/309");
  script_xref(name:"URL", value:"https://web.archive.org/web/20210213222518/http://www.securityfocus.com/bid/54068");

  script_tag(name:"summary", value:"Western Digital ShareSpace is prone to an information disclosure
  vulnerability.");

  script_tag(name:"vuldetect", value:"Send the crafted http GET request
  and check whether it is able to read the sensitive information or not.");

  script_tag(name:"insight", value:"The flaw exists due to an improper configuration
  of access rights of the configuration file config.xml");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote
  attacker to gain access to potentially sensitive information. By directly
  accessing the config.xml file without authentication it is possible to obtain
  system's configuration data, which includes network settings, shared folder
  names, SMB users and hashed passwords, administrator's credentials, etc.");

  script_tag(name:"affected", value:"WD ShareSpace versions through 2.3.02
  (D and E series).");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!get_app_location(port:port, cpe:CPE, nofork:TRUE))
  exit(0);

url = "/admin/config.xml";
if(http_vuln_check(port:port, url:url, pattern:"<certificate",
                   extra_check:make_list("<key", "<passwd>", "<htusers>", "<smblan", "<nfsright", "<emaillist", "<sharename", "<htpasswd"),
                   check_header:TRUE)) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
