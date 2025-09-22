# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:citrix:citrix_provisioning_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107132");
  script_version("2024-06-28T15:38:46+0000");
  script_tag(name:"last_modification", value:"2024-06-28 15:38:46 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"creation_date", value:"2017-01-20 16:11:25 +0700 (Fri, 20 Jan 2017)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-01-23 19:49:00 +0000 (Mon, 23 Jan 2017)");
  script_name("Citrix Provisioning Services Remote Code Execution and Information Disclosure Vulnerabilities");
  script_cve_id("CVE-2016-9676", "CVE-2016-9680", "CVE-2016-9677", "CVE-2016-9679", "CVE-2016-9678");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("General");
  script_dependencies("gb_citrix_provisioning_services_detect.nasl");
  script_mandatory_keys("Citrix/Provisioning/Services/Ver");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/95620");

  script_tag(name:"impact", value:"Successfully exploiting these issues may allow remote attackers to execute arbitrary code in the context of the
  application or obtain potentially sensitive information. Failed exploits may result in denial-of-service conditions.");

  script_tag(name:"affected", value:"Citrix Provisioning Services versions 7.6, 7.11, 7.7, 7.8, 7.9, 7.1 and 7.0.");

  script_tag(name:"solution", value:"Update to Citrix Provisioning Services 7.12.");

  script_tag(name:"summary", value:"Citrix Provisioning Services is prone to multiple remote code
  execution (RCE) and information disclosure vulnerabilities.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if (!version = get_app_version(cpe:CPE))
  exit(0);

model = get_kb_item("Citrix/Provisioning/Services/model");

if (version =~ "^7\.") {
  if (model == "LTSR" && version =~ "^7\.6\." && version_is_less(version:version, test_version:"7.6.4")) {
    vuln = TRUE;
    fixed = "7.6.4" + " LTSR";
    version = version + " LTSR";
  } else if (version_is_less(version:version, test_version:"7.12")) {
    vuln = TRUE;
    fixed = "7.12";
  }
}

if (vuln) {
  report = report_fixed_ver(installed_version:version, fixed_version:fixed);
  security_message(data:report);
  exit(0);
}

exit(99);
