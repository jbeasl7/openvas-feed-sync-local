# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cmsmadesimple:cms_made_simple";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.128001");
  script_version("2025-04-11T15:45:04+0000");
  script_tag(name:"last_modification", value:"2025-04-11 15:45:04 +0000 (Fri, 11 Apr 2025)");
  script_tag(name:"creation_date", value:"2024-03-08 12:00:00 +0000 (Fri, 08 Mar 2024)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-02-26 15:38:35 +0000 (Wed, 26 Feb 2025)");

  script_cve_id("CVE-2024-27622", "CVE-2024-27623", "CVE-2024-27625");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("CMS Made Simple <= 2.2.20 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_cms_made_simple_http_detect.nasl");
  script_mandatory_keys("cmsmadesimple/detected");

  script_tag(name:"summary", value:"CMS Made Simple is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2024-27622: Remote code execution where authenticated users with administrative privileges
  can inject and execute arbitrary PHP code due to inadequate sanitization of user-supplied input
  in the Code section of the module.

  - CVE-2024-27623: Server-Side Template Injection vulnerability in Design Manager
  when editing Breadcrumbs.

  - CVE-2024-27625: Cross Site Scripting in File Manager module of the admin panel due to
  inadequate sanitization of user input in the New directory field.");

  script_tag(name:"affected", value:"CMS Made Simple version 2.2.20 and prior.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_xref(name:"URL", value:"https://www.incibe.es/en/incibe-cert/notices/aviso/multiple-vulnerabilities-cms-made-simple");
  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/177243/CMS-Made-Simple-2.2.19-Cross-Site-Scripting.html");
  script_xref(name:"URL", value:"https://github.com/capture0x/CMSMadeSimple2");
  script_xref(name:"URL", value:"https://github.com/capture0x/CMSMadeSimple");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less_equal(version: version, test_version: "2.2.20")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "None", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
