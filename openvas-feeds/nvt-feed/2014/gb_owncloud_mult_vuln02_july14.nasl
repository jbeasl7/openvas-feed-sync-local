# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:owncloud:owncloud";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804657");
  script_version("2024-02-20T05:05:48+0000");
  script_cve_id("CVE-2014-2051", "CVE-2014-2053", "CVE-2014-2054", "CVE-2014-2055",
                "CVE-2014-2056");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-20 05:05:48 +0000 (Tue, 20 Feb 2024)");
  script_tag(name:"creation_date", value:"2014-07-03 12:20:12 +0530 (Thu, 03 Jul 2014)");
  script_name("ownCloud Multiple Vulnerabilities-02 (Jul 2014)");

  script_tag(name:"summary", value:"ownCloud is prone to multiple vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - The program fails to properly sanitize LDAP queries.

  - An incorrectly configured XML parser accepting XML external entities from an
  untrusted source");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to gain information about
existing LDAP users and potentially modify the login query, read arbitrary files,
cause a denial of service, or possibly have other impact via an XML External
Entity (XXE) attack.");
  script_tag(name:"affected", value:"ownCloud Server 5.0.x before 5.0.15 and 6.0.x before 6.0.2");
  script_tag(name:"solution", value:"Update to version 5.0.15 or 6.0.2 or later.");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/57283");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66172");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66218");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66220");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66225");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66226");
  script_xref(name:"URL", value:"http://owncloud.org/about/security/advisories/oC-SA-2014-005");
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

if(version_in_range(version:version, test_version:"5.0.0", test_version2:"5.0.14")||
   version_in_range(version:version, test_version:"6.0.0", test_version2:"6.0.1")) {
  security_message(port:port);
  exit(0);
}

exit(99);
