# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:aprox:aproxengine";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100426");
  script_version("2025-09-17T05:39:26+0000");
  script_tag(name:"last_modification", value:"2025-09-17 05:39:26 +0000 (Wed, 17 Sep 2025)");
  script_tag(name:"creation_date", value:"2010-01-05 18:50:28 +0100 (Tue, 05 Jan 2010)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("AproxEngine Multiple Remote Input Validation Vulnerabilities (Feb 2009)");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("AproxEngine_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("aproxengine/installed");

  script_tag(name:"summary", value:"AproxEngine is prone to multiple input-validation vulnerabilities,
  including SQL-injection, HTML-injection, directory-traversal, and email-spoofing issues.");

  script_tag(name:"impact", value:"Attackers can exploit these issues to execute arbitrary script code in the context of the webserver, compromise
  the application, obtain sensitive information, steal cookie-based authentication credentials from legitimate
  users of the site, modify the way the site is rendered, perform certain unauthorized actions in the context of
  a user, access or modify data, or exploit latent vulnerabilities in the underlying database.

  Attackers may require administrative privileges to exploit some of these issues.");

  script_tag(name:"affected", value:"AproxEngine 5.3.04 and 6.0 are vulnerable. Other versions may also be affected.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37515");
  script_xref(name:"URL", value:"http://secunia.com/secunia_research/2009-2/");
  script_xref(name:"URL", value:"http://www.aprox.de/index.php?id=1");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/508641");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

vers = infos["version"];
dir = infos["location"];

if (version_is_equal(version: vers, test_version: "5.3.04")) {
  security_message(port:port);
  exit(0);
}
else if (version_is_equal(version: vers, test_version: "6")) {
  if (dir == "/")
    dir = "";

  url = dir + "/engine/inc/sql_login.inc";
  req = http_get(item:url, port:port);
  buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
  if(!buf)
    exit(0);

  #  build 03.12.2009 is vulnerable. builds after 03.12.2009 are patched.
  if(egrep(pattern: "AproxEngine Version V6 build 03.12.2009", string: buf)) {
    security_message(port:port);
    exit(0);
  }
}

exit(0);
