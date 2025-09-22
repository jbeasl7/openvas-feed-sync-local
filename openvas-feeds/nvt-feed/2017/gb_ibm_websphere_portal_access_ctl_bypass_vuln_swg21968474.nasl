# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ibm:websphere_portal";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810733");
  script_version("2024-02-26T14:36:40+0000");
  script_cve_id("CVE-2015-4997");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-26 14:36:40 +0000 (Mon, 26 Feb 2024)");
  script_tag(name:"creation_date", value:"2017-04-07 17:09:57 +0530 (Fri, 07 Apr 2017)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("IBM WebSphere Portal Access Control Bypass Vulnerability (swg22000152)");

  script_tag(name:"summary", value:"IBM Websphere Portal is prone to access control bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an improper validation
  of access control. By sending specially crafted requests, an attacker could
  exploit this vulnerability to bypass security and gain unauthorized access
  to the vulnerable system or other systems.");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote
  attacker to bypass access control restrictions and gain access to the target
  system.");

  script_tag(name:"affected", value:"IBM WebSphere Portal 8.5.0 before Cumulative Fix 08 (CF08)");

  script_tag(name:"solution", value:"Upgrade to IBM WebSphere Portal
  8.5.0 with Cumulative Fix 08 (CF08) later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21968474");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1033982");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1PI47694");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_ibm_websphere_portal_detect.nasl");
  script_mandatory_keys("ibm_websphere_portal/installed");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!webPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!webVer = get_app_version(cpe:CPE, port:webPort)){
 exit(0);
}

if(webVer =~ "^8\.5\.0")
{
  if(version_is_less(version:webVer, test_version:"8.5.0.0.8"))
  {
    report = report_fixed_ver(installed_version:webVer, fixed_version:"8.5.0 Cumulative Fix 08 (CF08) or later");
    security_message(data:report, port:webPort);
    exit(0);
  }
}
