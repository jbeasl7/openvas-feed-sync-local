# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:bea:weblogic_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807566");
  script_version("2024-02-20T05:05:48+0000");
  script_cve_id("CVE-2016-0638", "CVE-2016-3416", "CVE-2016-0675", "CVE-2016-0700",
                "CVE-2016-0688", "CVE-2016-0696", "CVE-2014-4217", "CVE-2013-5855",
                "CVE-2014-2481", "CVE-2014-2480", "CVE-2014-2479", "CVE-2014-4267",
                "CVE-2014-4256", "CVE-2014-4202", "CVE-2014-4253", "CVE-2014-4242",
                "CVE-2014-4255", "CVE-2014-4254", "CVE-2014-4201", "CVE-2014-4210",
                "CVE-2014-2470");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-20 05:05:48 +0000 (Tue, 20 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-30 16:27:00 +0000 (Tue, 30 Oct 2018)");
  script_tag(name:"creation_date", value:"2016-05-03 17:27:14 +0530 (Tue, 03 May 2016)");

  script_name("Oracle WebLogic Server Multiple Unspecified Vulnerabilities -01 (May 2016)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_oracle_weblogic_consolidation.nasl");
  script_mandatory_keys("oracle/weblogic/detected");

  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/security-advisory/cpuapr2016v3-2985753.html");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/cpujul2014-1972956.html");

  script_tag(name:"summary", value:"Oracle WebLogic Server is prone to multiple unspecified vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to multiple unspecified vulnerabilities in Oracle Fusion Middleware.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to have an impact on
  confidentiality, integrity, and availability.");

  script_tag(name:"affected", value:"Oracle WebLogic Server versions 10.3.6.0, 12.1.2.0, 12.1.3.0, 12.1.1.0,
  12.2.1.0 and 10.0.2.0.");

  script_tag(name:"solution", value:"Apply the updates from the referenced advisories.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!version = get_app_version(cpe:CPE, nofork:TRUE))
  exit(0);

if(version_is_equal(version:version, test_version:"10.3.6.0.0") ||
   version_is_equal(version:version, test_version:"12.1.2.0.0") ||
   version_is_equal(version:version, test_version:"12.1.3.0.0") ||
   version_is_equal(version:version, test_version:"12.2.1.0.0") ||
   version_is_equal(version:version, test_version:"12.1.1.0.0") ||
   version_is_equal(version:version, test_version:"10.0.2.0.0")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"See advisory");
  security_message(data:report, port:0);
  exit(0);
}

exit(99);
