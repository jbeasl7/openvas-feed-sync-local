# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:owncloud:owncloud";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804662");
  script_version("2024-02-20T05:05:48+0000");
  script_cve_id("CVE-2014-3833", "CVE-2014-3835", "CVE-2014-3838");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-20 05:05:48 +0000 (Tue, 20 Feb 2024)");
  script_tag(name:"creation_date", value:"2014-07-03 16:47:48 +0530 (Thu, 03 Jul 2014)");
  script_name("ownCloud Multiple Vulnerabilities-04 (Jul 2014)");

  script_tag(name:"summary", value:"ownCloud is prone to multiple vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Multiple flaws are due to:

  - Input passed on to 'print_unescaped' function in the Gallery component is not
  sufficiently validated before returning it to users.

  - The program fails to verify whether a user has been granted access to add
  external storages or not.

  - The server fails to properly perform authorization checks in core when
  handling user accounts.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to mount an external
storage without permission, access the file names of other users and execute
arbitrary script code in a user's browser session within the trust relationship
between their browser and the server.");
  script_tag(name:"affected", value:"ownCloud Server 5.0.x before 5.0.16 and 6.0.x before 6.0.3");
  script_tag(name:"solution", value:"Update to version 5.0.16 or 6.0.3 or later.");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/93687");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67451");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/68059");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/68060");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");
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

if(version_in_range(version:version, test_version:"5.0.0", test_version2:"5.0.15")||
   version_in_range(version:version, test_version:"6.0.0", test_version2:"6.0.2")) {
  security_message(port:port);
  exit(0);
}

exit(99);
