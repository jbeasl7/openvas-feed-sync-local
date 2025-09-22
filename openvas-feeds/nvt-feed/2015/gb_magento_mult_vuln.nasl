# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:magentocommerce:magento";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805372");
  script_version("2024-03-04T14:37:58+0000");
  script_cve_id("CVE-2015-1397", "CVE-2015-1398", "CVE-2015-1399", "CVE-2015-3457",
                "CVE-2015-3458");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-03-04 14:37:58 +0000 (Mon, 04 Mar 2024)");
  script_tag(name:"creation_date", value:"2015-04-29 17:25:37 +0530 (Wed, 29 Apr 2015)");
  script_name("Magento Web E-Commerce Platform Multiple Vulnerabilities");

  script_tag(name:"summary", value:"Magento Web E-Commerce Platform is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - The admin session are not properly validated, It fails to detect controller
    injection technique.

  - The admin templates filters are not properly validated before being returned
    to the user.

  - The 'from' and 'to' keys are not properly validated before being returned
    to the user.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary code on the affected system.");

  script_tag(name:"affected", value:"Magento version 1.9.1.0 CE.");

  script_tag(name:"solution", value:"Apply the patch manually.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"http://blog.checkpoint.com/2015/04/20/analyzing-magento-vulnerability/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/74298");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/74420");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/74412");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("sw_magento_detect.nasl");
  script_mandatory_keys("magento/installed");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!version = get_app_version(cpe:CPE, port:port))
  exit(0);

if(version_is_equal(version:version, test_version:"1.9.1.0")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"Apply appropriate patch");
  security_message(data:report, port:port);
  exit(0);
}

exit(99);
