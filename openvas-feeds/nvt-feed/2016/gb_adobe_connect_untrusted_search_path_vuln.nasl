# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:connect";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808062");
  script_version("2023-09-15T16:10:33+0000");
  script_tag(name:"last_modification", value:"2023-09-15 16:10:33 +0000 (Fri, 15 Sep 2023)");
  script_tag(name:"creation_date", value:"2016-06-07 16:34:52 +0530 (Tue, 07 Jun 2016)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-11-29 02:29:00 +0000 (Wed, 29 Nov 2017)");

  script_cve_id("CVE-2016-4118");

  # nb: Users can still update their Add-In to a newer version
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Adobe Connect < 9.5.3 Untrusted Search Path Vulnerability (APSB16-17)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("General");
  script_dependencies("gb_adobe_connect_http_detect.nasl");
  script_mandatory_keys("adobe/connect/detected");

  script_tag(name:"summary", value:"Adobe Connect shipping an Adobe Connect Add-In for Windows is
  prone to a untrusted search path vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an error in the Adobe Connect Add-In
  installer while validating the path.");

  script_tag(name:"impact", value:"Successful exploitation will allow local users of the System
  which is using the vulnerable Adobe Connect Add-In to gain privileges via unspecified vectors.");

  script_tag(name:"affected", value:"Adobe Connect prior to version 9.5.3.");

  script_tag(name:"solution", value:"Update to version 9.5.3 or later.");

  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/connect/apsb16-17.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "9.5.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.5.3");
  security_message(port: port, data:report);
  exit(0);
}

exit(99);
