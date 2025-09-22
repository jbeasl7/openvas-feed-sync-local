# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802563");
  script_version("2024-06-27T05:05:29+0000");
  script_cve_id("CVE-2011-5048");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2024-06-27 05:05:29 +0000 (Thu, 27 Jun 2024)");
  script_tag(name:"creation_date", value:"2012-01-19 18:01:09 +0530 (Thu, 19 Jan 2012)");
  script_name("IBM Web Experience Factory Multiple XSS Vulnerabilities");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51246");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21575083");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Windows");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name:"insight", value:"The flaws are due to improper validation of user-supplied input to
  'INPUT' and 'TEXTAREA' elements.");

  script_tag(name:"solution", value:"Upgrade to the IBM Web Experience Factory 7.0.1.2 or later.");

  script_tag(name:"summary", value:"IBM Web Experience Factory is prone to multiple cross-site
  scripting (XSS) vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to execute arbitrary
  HTML and script code in a user's browser session in context of an affected site.");

  script_tag(name:"affected", value:"IBM Web Experience Factory version 7.0 and 7.0.1.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\IBM WebSphere Portlet Factory";
if(!registry_key_exists(key:key))
  exit(0);

ibmName = registry_get_sz(key:key, item:"DisplayName");
if("IBM WebSphere Portlet Factory" >< ibmName) {
  ibmVer = registry_get_sz(key:key, item:"DisplayVersion");
  if(ibmVer) {
    if(version_in_range(version:ibmVer, test_version:"7.0", test_version2:"7.0.1.0")) {
      report = report_fixed_ver(installed_version:ibmVer, fixed_version:"7.0.1.2", reg_checked:key + "!DisplayVersion");
      security_message(port:0, data:report);
      exit(0);
    }
  }
}

exit(99);
