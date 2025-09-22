# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:owncloud:owncloud";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804278");
  script_version("2024-02-20T05:05:48+0000");
  script_cve_id("CVE-2013-0301");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-20 05:05:48 +0000 (Tue, 20 Feb 2024)");
  script_tag(name:"creation_date", value:"2014-05-05 11:20:11 +0530 (Mon, 05 May 2014)");
  script_name("ownCloud Cross Site Request Forgery Vulnerability -01 (May 2014)");

  script_tag(name:"summary", value:"ownCloud is prone to a cross-site request forgery (CSRF) vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The flaw exists due to insufficient validation of user-supplied input passed
via the 'timezone' POST parameter to settimezone within
/apps/calendar/ajax/settings.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to conduct cross-site
request forgery attacks.");
  script_tag(name:"affected", value:"ownCloud Server before version 4.0.12");
  script_tag(name:"solution", value:"Update to version 4.0.12 or later.");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://seclists.org/oss-sec/2013/q1/378");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58107");
  script_xref(name:"URL", value:"http://owncloud.org/about/security/advisories/oC-SA-2013-004");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_owncloud_http_detect.nasl");
  script_mandatory_keys("owncloud/detected");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!version = get_app_version(cpe:CPE, port:port))
  exit(0);

if(version_is_less(version:version, test_version:"4.0.12")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"4.0.12");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
