# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:owncloud:owncloud";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809298");
  script_version("2024-02-15T05:05:40+0000");
  script_cve_id("CVE-2016-7419");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-04-07 19:38:00 +0000 (Fri, 07 Apr 2017)");
  script_tag(name:"creation_date", value:"2016-09-26 17:23:26 +0530 (Mon, 26 Sep 2016)");
  script_name("ownCloud 'share.js' Gallery Application XSS Vulnerability - Linux");

  script_tag(name:"summary", value:"ownCloud is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to a recent migration
  of the gallery app to the new sharing endpoint and a parameter changed from an
  integer to a string value which is not sanitized properly.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  authenticated users to inject arbitrary web script or HTML.");

  script_tag(name:"affected", value:"ownCloud Server before 9.0.4 on Linux.");

  script_tag(name:"solution", value:"Upgrade to ownCloud Server 9.0.4 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"https://owncloud.org/security/advisory/?id=oc-sa-2016-011");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_owncloud_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("owncloud/detected", "Host/runs_unixoide");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!version = get_app_version(cpe:CPE, port:port))
  exit(0);

if(version_is_less(version:version, test_version:"9.0.4")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"9.0.4");
  security_message(data:report, port:port);
  exit(0);
}

exit(99);
