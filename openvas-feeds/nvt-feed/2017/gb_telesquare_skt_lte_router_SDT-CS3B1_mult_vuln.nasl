# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/h:telesquare:sdt-cs3b1";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812367");
  script_version("2025-03-26T05:38:58+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-03-26 05:38:58 +0000 (Wed, 26 Mar 2025)");
  script_tag(name:"creation_date", value:"2017-12-28 11:04:35 +0530 (Thu, 28 Dec 2017)");
  script_name("Telesquare SKT LTE Router SDT-CS3B1 Multiple Vulnerabilities - Active Check");

  script_tag(name:"summary", value:"Telesquare SKT LTE Router SDT-CS3B1 devices are prone to
  multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send the crafted http GET request
  and check whether it is able to read the sensitive information or not.");

  script_tag(name:"insight", value:"Multiple vulnerabilities exist as,

  - Application provides direct access to objects based on user-supplied input.

  - Application allows unauthenticated user to execute reboot command.

  - Application interface allows users to perform certain actions via HTTP
    requests without performing any validity checks to verify the requests.");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote
  attacker to gain access to potentially sensitive information, bypass
  authorization and access resources and functionalities in the system and
  conduct a denial of service condition.");

  script_tag(name:"affected", value:"Telesquare SKT LTE Router SDT-CS3B1 devices in all versions.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_vul");

  script_xref(name:"URL", value:"https://www.zeroscience.mk/en/vulnerabilities/ZSL-2017-5445.php");
  script_xref(name:"URL", value:"https://www.zeroscience.mk/en/vulnerabilities/ZSL-2017-5444.php");
  script_xref(name:"URL", value:"https://www.zeroscience.mk/en/vulnerabilities/ZSL-2017-5443.php");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_telesquare_skt_lte_router_SDT-CS3B1_detect.nasl");
  script_mandatory_keys("telesquare/SDT-CS3B1/detected");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!get_app_location(port:port, cpe:CPE, nofork:TRUE))
  exit(0);

url = "/cgi-bin/systemutil.cgi?Command=SystemInfo";

if(http_vuln_check(port:port, url:url, pattern:"<Model>SDT-CS3B1<",
                   extra_check:make_list("<FwVer>SDT-CS3B1", "<LteVer>", "<CMState>", "<uicc_state>"),
                   check_header:TRUE)) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
