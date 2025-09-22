# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:owncloud:owncloud";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805282");
  script_version("2023-12-01T16:11:30+0000");
  script_cve_id("CVE-2014-9044");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-12-01 16:11:30 +0000 (Fri, 01 Dec 2023)");
  script_tag(name:"creation_date", value:"2015-02-19 16:14:16 +0530 (Thu, 19 Feb 2015)");
  script_name("ownCloud Asset Pipeline Feature Remote Path Disclosure Vulnerability (oC-SA-2014-021)");

  script_tag(name:"summary", value:"ownCloud is prone to a path disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The error exists due to flaw in the Asset
  Pipeline feature due to the program is generating files on the local filesystem
  with a filename that is created by hashing the original CSS and JS absolute
  file paths using MD5.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to conduct a brute-force attack and gain access to the
  installation path of the program.");

  script_tag(name:"affected", value:"ownCloud Server 7.x before 7.0.3");

  script_tag(name:"solution", value:"Upgrade to ownCloud Server 7.0.3 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"https://owncloud.org/security/advisory/?id=oc-sa-2014-021");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/71387");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_owncloud_http_detect.nasl");
  script_mandatory_keys("owncloud/detected");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!vers = get_app_version(cpe:CPE, port:port))
  exit(0);

if(vers =~ "^7") {
  if(version_in_range(version:vers, test_version:"7.0.0", test_version2:"7.0.2")) {
    report = 'Installed version: ' + vers + '\n' +
           'Fixed version:     ' + "7.0.3" + '\n';
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);
