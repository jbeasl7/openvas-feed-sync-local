# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:owncloud:owncloud";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805283");
  script_version("2023-12-01T16:11:30+0000");
  script_cve_id("CVE-2014-5341");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-12-01 16:11:30 +0000 (Fri, 01 Dec 2023)");
  script_tag(name:"creation_date", value:"2015-02-19 17:25:47 +0530 (Thu, 19 Feb 2015)");
  script_name("ownCloud 'files_external' RSA Key Validation Information Disclosure Vulnerability");

  script_tag(name:"summary", value:"ownCloud is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The error exists due to error in the SFTP
  external storage driver that is triggered as RSA Host Keys are verified after
  logging in.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to conduct man-in-the-middle attack and spoof a valid host key
  bypassing authentication.");

  script_tag(name:"affected", value:"ownCloud Server 6.x before 6.0.5");

  script_tag(name:"solution", value:"Upgrade to ownCloud Server 6.0.5 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"https://owncloud.org/security/advisory/?id=oc-sa-2014-019");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/70039");

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

if(!version = get_app_version(cpe:CPE, port:port))
  exit(0);

if(version =~ "^6") {
  if(version_in_range(version:version, test_version:"6.0.0", test_version2:"6.0.4")) {
    report = report_fixed_ver(installed_version:version, fixed_version:"6.0.5");
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);
