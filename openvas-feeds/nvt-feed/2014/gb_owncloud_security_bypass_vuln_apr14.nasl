# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:owncloud:owncloud";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804363");
  script_version("2024-02-20T05:05:48+0000");
  script_cve_id("CVE-2014-2585");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2024-02-20 05:05:48 +0000 (Tue, 20 Feb 2024)");
  script_tag(name:"creation_date", value:"2014-04-04 18:54:56 +0530 (Fri, 04 Apr 2014)");
  script_name("ownCloud Local Filesystem Mounting Security Bypass Vulnerability (Apr 2014)");

  script_tag(name:"summary", value:"ownCloud is prone to a security bypass vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The flaw is due to the server failing to properly sanitize mount
configurations.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attacker to mount the local
filesystem and gain access to the information contained within it.");
  script_tag(name:"affected", value:"ownCloud Server version 5.x before 5.0.15 and 6.x before 6.0.2");
  script_tag(name:"solution", value:"Update to version 5.0.15 or 6.0.2 or later.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/57283");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66451");
  script_xref(name:"URL", value:"http://owncloud.org/about/security/advisories/oC-SA-2014-008");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_owncloud_http_detect.nasl");
  script_mandatory_keys("owncloud/detected");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!version = get_app_version(cpe:CPE, port:port))
  exit(0);

if(version_in_range(version:version, test_version:"5.0.0", test_version2:"5.0.14")||
   version_in_range(version:version, test_version:"6.0", test_version2:"6.0.1")) {
  security_message(port:port);
  exit(0);
}

exit(99);
