# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:owncloud:owncloud";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804282");
  script_version("2023-12-01T16:11:30+0000");
  script_cve_id("CVE-2014-2049");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-12-01 16:11:30 +0000 (Fri, 01 Dec 2023)");
  script_tag(name:"creation_date", value:"2014-05-06 15:24:42 +0530 (Tue, 06 May 2014)");
  script_name("ownCloud Flash Cross-Domain Information Disclosure Vulnerability");

  script_tag(name:"summary", value:"ownCloud is prone to cross domain information disclosure vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The flaw is due to unspecified error related to flash cross-domain policies.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to gain access to a user's
stored files.");
  script_tag(name:"affected", value:"ownCloud Server before version 5.0.15 and 6.x before version 6.0.2");
  script_tag(name:"solution", value:"Update to version 5.0.15 or 6.0.2 or later.");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://owncloud.org/about/security/advisories/oC-SA-2014-003");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66229");
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

if(version_is_less(version:version, test_version:"5.0.15")||
   version_in_range(version:version, test_version:"6.0.0", test_version2:"6.0.1")) {
  security_message(port:port);
  exit(0);
}

exit(99);
