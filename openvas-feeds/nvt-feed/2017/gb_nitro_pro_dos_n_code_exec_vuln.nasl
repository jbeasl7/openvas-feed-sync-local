# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:nitro_software:nitro_pro";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811273");
  script_version("2024-02-15T05:05:40+0000");
  script_cve_id("CVE-2017-7950", "CVE-2017-2796");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-04 13:56:00 +0000 (Tue, 04 Aug 2020)");
  script_tag(name:"creation_date", value:"2017-08-04 16:25:44 +0530 (Fri, 04 Aug 2017)");
  script_name("Nitro Pro Denial-of-Service and Code Execution Vulnerabilities - Windows");

  script_tag(name:"summary", value:"Nitro Pro is prone to denial of service (DoS) and code execution
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to improper handling
  of a crafted PCX file and an out of bound write error in the PDF parsing
  functionality");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to conduct a denial-of-service (application crash) condition and
  execute arbitrary code on the affected system.");

  script_tag(name:"affected", value:"Nitro Pro version 11.0.3 (11.0.3.134)
  and prior.");

  script_tag(name:"solution", value:"Upgrade to Nitro Pro version 11.0.3.173
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://www.gonitro.com/product/downloads#securityUpdates");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99514");
  script_xref(name:"URL", value:"https://www.talosintelligence.com/vulnerability_reports/TALOS-2017-0289");

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_nitro_pro_detect_win.nasl");
  script_mandatory_keys("Nitro/Pro/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!nitroVer = get_app_version(cpe:CPE, nofork:TRUE))
  exit(0);

if(version_is_less(version:nitroVer, test_version:"11.0.3.173")) {
  report = report_fixed_ver(installed_version:nitroVer, fixed_version:"11.0.3.173");
  security_message(data:report);
  exit(0);
}

exit(99);
