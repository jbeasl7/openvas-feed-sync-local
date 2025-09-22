# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:squid-cache:squid";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806518");
  script_version("2023-07-25T05:05:58+0000");
  script_cve_id("CVE-2015-5400");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-10-28 17:35:29 +0530 (Wed, 28 Oct 2015)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("Squid 'cache_peer' Security Bypass Vulnerability (SQUID-2015:2)");

  script_tag(name:"summary", value:"Squid is prone to an access bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to improper handling of
  CONNECT method peer responses when configured with cache_peer.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to bypass security in an explicit gateway proxy.");

  script_tag(name:"affected", value:"Squid version 3.5.5 and prior.");

  script_tag(name:"solution", value:"Update to version 3.5.6 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.squid-cache.org/Advisories/SQUID-2015_2.txt");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/75553");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2015/07/09/12");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_squid_http_detect.nasl");
  script_mandatory_keys("squid/detected");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!vers = get_app_version(cpe:CPE, port:port))
  exit(0);

if(version_is_less(version:vers, test_version:"3.5.6")) {
  report = 'Installed version: ' + vers + '\n' +
           'Fixed version:     3.5.6\n';
  security_message(data:report, port:port);
  exit(0);
}

exit(99);
