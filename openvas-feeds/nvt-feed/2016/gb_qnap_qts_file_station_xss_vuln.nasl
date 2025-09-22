# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:qnap:qts";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808247");
  script_version("2023-09-27T05:05:31+0000");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-09-27 05:05:31 +0000 (Wed, 27 Sep 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-09-01 01:29:00 +0000 (Fri, 01 Sep 2017)");
  script_tag(name:"creation_date", value:"2016-07-05 16:44:34 +0530 (Tue, 05 Jul 2016)");

  script_cve_id("CVE-2015-5664");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("QNAP QTS File Station XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_qnap_nas_http_detect.nasl");
  script_mandatory_keys("qnap/nas/qts/detected");

  script_tag(name:"summary", value:"QNAP QTS File Station is prone to a cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an insufficient validation of user supplied
  input via unspecified vectors in File Station.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to inject
  arbitrary web script or HTML via unspecified vectors.");

  script_tag(name:"affected", value:"QNAP QTS versions prior to 4.2.1 Build 20160601");

  script_tag(name:"solution", value:"Upgrade to QNAP QTS version
  4.2.1 Build 20160601 or later.");

  script_xref(name:"URL", value:"http://jvn.jp/en/jp/JVN42930233/index.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/91474");
  script_xref(name:"URL", value:"http://jvndb.jvn.jp/en/contents/2016/JVNDB-2016-000119.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe:CPE, nofork:TRUE))
  exit(0);

build = get_kb_item("qnap/nas/qts/build");

if (version_is_less(version:version, test_version:"4.2.1") ||
   (version_is_equal(version:version, test_version:"4.2.1") &&
   (!build || version_is_less(version:build, test_version:"20160601"))))
{
  report = report_fixed_ver(installed_version:version, installed_build:build, fixed_version:"4.2.1", fixed_build:"20160601");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
