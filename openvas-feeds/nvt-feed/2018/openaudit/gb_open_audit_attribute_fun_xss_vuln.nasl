# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:opmantek:open-audit";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813675");
  script_version("2024-03-04T14:37:58+0000");
  script_cve_id("CVE-2018-11124");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2024-03-04 14:37:58 +0000 (Mon, 04 Mar 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-09-02 13:52:00 +0000 (Sun, 02 Sep 2018)");
  script_tag(name:"creation_date", value:"2018-07-16 12:35:38 +0530 (Mon, 16 Jul 2018)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_name("Open-AudIT Community 'Attributes' Functionality Cross Site Scripting Vulnerability");

  script_tag(name:"summary", value:"Open-AudIT is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an insufficient sanitization
  of attribute name of an Attribute.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to inject arbitrary web script or HTML.");

  script_tag(name:"affected", value:"Open-AudIT Community versions prior to 2.2.2");

  script_tag(name:"solution", value:"Upgrade to Open-AudIT Community version 2.2.2
  or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://docs.google.com/document/d/1dJP1CQupHGXjsMWthgPGepOkcnxYA4mDfdjOE46nrhM");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_open_audit_detect.nasl");
  script_mandatory_keys("open-audit/detected");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if (!port = get_app_port(cpe:CPE))
  exit(0);

if (!version = get_app_version(cpe:CPE, port:port))
  exit(0);

if(version_is_less(version:version, test_version:"2.2.2")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"2.2.2");
  security_message(data:report, port:port);
  exit(0);
}

exit(99);
