# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ibm:tivoli_endpoint_manager";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809367");
  script_version("2024-03-04T14:37:58+0000");
  script_cve_id("CVE-2014-3066");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-03-04 14:37:58 +0000 (Mon, 04 Mar 2024)");
  script_tag(name:"creation_date", value:"2016-10-18 13:23:56 +0530 (Tue, 18 Oct 2016)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("IBM Tivoli Endpoint Manager XML External Entity Injection Vulnerability");

  script_tag(name:"summary", value:"IBM Tivoli Endpoint Manager is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is caused by an XML External Entity
  Injection (XXE) error when processing XML data.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to read arbitrary files via XML data containing an external entity
  declaration in conjunction with an entity reference.");

  script_tag(name:"affected", value:"IBM Tivoli Endpoint Manager versions
  9.1 prior to 9.1.1088.0");

  script_tag(name:"solution", value:"Upgrade to IBM Tivoli Endpoint Manager
  version 9.1.1088.0, or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21673951");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/78017");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_ibm_endpoint_manager_web_detect.nasl");
  script_mandatory_keys("ibm_endpoint_manager/installed");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!version = get_app_version(cpe:CPE, port:port))
  exit(0);

if(version_in_range(version:version, test_version:"9.1", test_version2:"9.1.1087.0")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"9.1.1088.0");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
