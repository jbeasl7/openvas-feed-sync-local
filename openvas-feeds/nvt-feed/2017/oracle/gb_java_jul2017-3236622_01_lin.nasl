# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108375");
  script_version("2025-01-21T05:37:33+0000");
  script_cve_id("CVE-2017-10198", "CVE-2017-10096", "CVE-2017-10135", "CVE-2017-10110",
                "CVE-2017-10115", "CVE-2017-10116", "CVE-2017-10074", "CVE-2017-10053",
                "CVE-2017-10087", "CVE-2017-10089", "CVE-2017-10243", "CVE-2017-10102",
                "CVE-2017-10101", "CVE-2017-10107", "CVE-2017-10109", "CVE-2017-10105",
                "CVE-2017-10081", "CVE-2017-10193", "CVE-2017-10067", "CVE-2017-10108");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-10-06 19:03:00 +0000 (Thu, 06 Oct 2022)");
  script_tag(name:"creation_date", value:"2017-07-19 11:49:40 +0530 (Wed, 19 Jul 2017)");
  script_name("Oracle Java SE Security Updates (jul2017-3236622) 01 - Linux");

  script_tag(name:"summary", value:"Oracle Java SE is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to multiple
  unspecifide errors in 'Security', 'AWT', 'ImageIO', 'JAXP', 'Libraries',
  'RMI', 'Hotspot', 'JCE', 'JAX-WS', '2D', 'Serialization', 'Deployment'
  component of the application.");

  script_tag(name:"impact", value:"Successful exploitation of this
  vulnerability will allow remote attackers to have an impact on
  confidentiality, integrity and availability.");

  script_tag(name:"affected", value:"Oracle Java SE version 1.6.0.151 and
  earlier, 1.7.0.141 and earlier, 1.8.0.131 and earlier on Linux.");

  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/security-advisory/cpujul2017-3236622.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99818");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99670");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99839");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99643");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99774");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99734");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99731");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99842");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99703");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99659");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99827");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99712");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99674");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99719");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99847");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99851");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99853");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99854");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99756");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99846");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("General");
  script_dependencies("gb_java_prdts_detect_lin.nasl");
  script_mandatory_keys("Sun/Java/JRE/Linux/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/a:oracle:jre", "cpe:/a:oracle:jdk", "cpe:/a:sun:jre", "cpe:/a:sun:jdk");

if(!infos = get_app_version_and_location_from_list(cpe_list:cpe_list, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_in_range(version:vers, test_version:"1.6.0", test_version2:"1.6.0.151") ||
   version_in_range(version:vers, test_version:"1.7.0", test_version2:"1.7.0.141") ||
   version_in_range(version:vers, test_version:"1.8.0", test_version2:"1.8.0.131")) {
  report = report_fixed_ver(installed_version:vers, fixed_version: "Apply the patch", install_path:path);
  security_message(data:report);
  exit(0);
}

exit(99);
