# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mcafee:web_gateway";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804839");
  script_version("2024-03-04T14:37:58+0000");
  script_cve_id("CVE-2014-6064");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-03-04 14:37:58 +0000 (Mon, 04 Mar 2024)");
  script_tag(name:"creation_date", value:"2014-09-09 17:31:29 +0530 (Tue, 09 Sep 2014)");

  script_name("McAfee Web Gateway Information Disclosure Vulnerability");

  script_tag(name:"summary", value:"McAfee Web Gateway is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an error in admin
  interface while viewing the top level Accounts tab");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  authenticated remote attacker to gain access to SHA1 hashed MWG administrator
  password information.");

  script_tag(name:"affected", value:"McAfee Web Gateway before 7.3.2.9 and
  7.4.x before 7.4.2");

  script_tag(name:"solution", value:"Upgrade to McAfee Web Gateway version
  7.3.2.9 or 7.4.2 or later.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1030675");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69556");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_dependencies("gb_mcafee_web_gateway_detect.nasl");
  script_mandatory_keys("McAfee/Web/Gateway/installed");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!version = get_app_version(cpe:CPE, port:port))
  exit(0);

if(version_is_less(version:version, test_version:"7.3.2.9")){
  report = report_fixed_ver(installed_version:version, fixed_version:"7.3.2.9");
  security_message(port:port, data:report);
  exit(0);
}

if(version =~ "^7\.4") {
  if(version_is_less(version:version, test_version:"7.4.2")) {
    report = report_fixed_ver(installed_version:version, fixed_version:"7.4.2");
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);
