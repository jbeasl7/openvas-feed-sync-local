# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:eterna:bozohttpd";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801246");
  script_version("2023-07-28T16:09:07+0000");
  script_cve_id("CVE-2010-2320");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-08-06 17:02:44 +0200 (Fri, 06 Aug 2010)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("bozotic HTTP server Information Disclosure Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_bozotic_http_server_detect.nasl");
  script_mandatory_keys("bozohttpd/detected");

  script_xref(name:"URL", value:"http://secunia.com/advisories/40737");
  script_xref(name:"URL", value:"http://www.eterna.com.au/bozohttpd/CHANGES");
  script_xref(name:"URL", value:"http://security-tracker.debian.org/tracker/CVE-2010-2320");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to determine the existence of a
  user and potentially disclose the user's files.");

  script_tag(name:"affected", value:"bozotic HTTP server (aka bozohttpd) versions before 20100621.");

  script_tag(name:"insight", value:"The server is not properly handling requests to a user's public_html folder
  while the folder does not exist. This can be exploited to determine the
  existence of user accounts via multiple requests for URIs beginning with
  /~ sequences.");

  script_tag(name:"solution", value:"Upgrade to bozotic HTTP server version 20100621 or later.");

  script_tag(name:"summary", value:"bozotic HTTP server is prone to an information disclosure vulnerability.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!vers = get_app_version(port:port, cpe:CPE))
  exit(0);

if(version_is_less(version:vers, test_version:"20100621")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"20100621");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);