# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:joomla:joomla";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112051");
  script_version("2023-07-25T05:05:58+0000");
  script_cve_id("CVE-2015-5608");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-09-22 23:16:00 +0000 (Fri, 22 Sep 2017)");
  script_tag(name:"creation_date", value:"2017-09-21 10:36:22 +0200 (Thu, 21 Sep 2017)");
  script_name("Joomla! Open Redirect Vulnerability");

  script_tag(name:"summary", value:"Joomla is prone to an open redirect vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Joomla is prone to the following open redirect vulnerability:

  - Inadequate checking of the return value allowed to redirect to an external page.");

  script_tag(name:"affected", value:"Joomla! versions 3.0.0 through 3.4.1");

  script_tag(name:"solution", value:"Upgrade to Joomla version 3.4.2 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"https://developer.joomla.org/security-centre/617-20150601-core-open-redirect.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/76496");

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl");
  script_mandatory_keys("joomla/installed");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE)){
  exit(0);
}

if(!ver = get_app_version(cpe:CPE, port:port)){
  exit(0);
}

if(version_in_range(version:ver, test_version:"3.0.0", test_version2:"3.4.1"))
{
  report = report_fixed_ver(installed_version:ver, fixed_version:"3.4.2");
  security_message(data:report, port:port);
  exit(0);
}
exit(99);
