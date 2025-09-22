# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ibm:tivoli_endpoint_manager";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809397");
  script_version("2024-03-04T14:37:58+0000");
  script_cve_id("CVE-2012-1837");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-03-04 14:37:58 +0000 (Mon, 04 Mar 2024)");
  script_tag(name:"creation_date", value:"2016-11-15 13:41:38 +0100 (Tue, 15 Nov 2016)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("IBM Tivoli Endpoint Manager 'HTTPOnly flag' Information Disclosure Vulnerability");

  script_tag(name:"summary", value:"IBM Tivoli Endpoint Manager is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to the webreports,
  post/create-role, and post/update-role programs do not include the HTTPOnly
  flag in a Set-Cookie header for a cookie.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to obtain potentially sensitive information.");

  script_tag(name:"affected", value:"IBM Tivoli Endpoint Manager versions
  before 8.2.");

  script_tag(name:"solution", value:"Upgrade to IBM Tivoli Endpoint Manager
  version 8.2. or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://infosec.cert-pa.it/cve-2012-1837.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/78246");

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

if(version_is_less(version:version, test_version:"8.2")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"8.2");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
