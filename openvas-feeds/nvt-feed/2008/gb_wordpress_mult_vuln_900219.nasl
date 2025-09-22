# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900219");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2008-09-25 09:10:39 +0200 (Thu, 25 Sep 2008)");
  script_cve_id("CVE-2008-3747");
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_name("WordPress <= 2.6.1 Multiple Vulnerabilities");
  script_dependencies("gb_wordpress_http_detect.nasl");
  script_mandatory_keys("wordpress/detected");
  script_xref(name:"URL", value:"http://www.sektioneins.de/advisories/SE-2008-05.txt");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/30750");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/31068");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/31115");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2008/Sep/0194.html");
  script_xref(name:"URL", value:"http://www.juniper.net/security/auto/vulnerabilities/vuln31068.html");
  script_xref(name:"URL", value:"http://www.juniper.net/security/auto/vulnerabilities/vuln30750.html");

  script_tag(name:"summary", value:"WordPress is prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"The flaws are due to:

  - SQL column-truncation issue.

  - Weakness in the entropy of generated passwords.

  - functions get_edit_post_link(), and get_edit_comment_link() fail
  to use SSL when transmitting data.");

  script_tag(name:"affected", value:"WordPress 2.6.1 and prior versions.");

  script_tag(name:"solution", value:"Update to version 2.6.2 or later.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to reset the
  password of arbitrary accounts, guess randomly generated passwords, obtain sensitive information
  and possibly to impersonate users and amper with network data.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!ver = get_app_version(cpe:CPE, port:port))
  exit(0);

if(version_is_less(version:ver, test_version:"2.6.2")){
  report = report_fixed_ver(installed_version:ver, fixed_version:"2.6.2");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
