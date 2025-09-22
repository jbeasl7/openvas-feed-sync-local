# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:linksys:e5600_firmware";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.128128");
  script_version("2025-05-15T05:40:37+0000");
  script_tag(name:"last_modification", value:"2025-05-15 05:40:37 +0000 (Thu, 15 May 2025)");
  script_tag(name:"creation_date", value:"2025-05-14 13:10:13 +0000 (Wed, 14 May 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-05-13 20:19:39 +0000 (Tue, 13 May 2025)");

  script_cve_id("CVE-2025-45487", "CVE-2025-45488", "CVE-2025-45489", "CVE-2025-45490",
                "CVE-2025-45491");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_name("Linksys E5600 Router <= 1.1.0.26 Multiple Command Injection Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_linksys_devices_consolidation.nasl");
  script_mandatory_keys("linksys/detected");

  script_tag(name:"summary", value:"Linksys E5600 routers are prone to multiple command injection
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2025-45487: Command injection vulnerability in the runtime.InternetConnection function.

  - CVE-2025-45488: Command injection vulnerability in the runtime.ddnsStatus DynDNS function via
    the mailex parameter.

  - CVE-2025-45489: Command injection vulnerability in the runtime.ddnsStatus DynDNS function via
    the hostname parameter.

  - CVE-2025-45490: Command injection vulnerability in the runtime.ddnsStatus DynDNS function via
    the password parameter.

  - CVE-2025-45491: Command injection vulnerability in the runtime.ddnsStatus DynDNS function via
    the username parameter.");

  script_tag(name:"affected", value:"Linksys E5600 routers with firmware versions 1.1.0.26 and
  prior.");

  script_tag(name:"solution", value:"No known solution is available as of 14th May, 2025.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://github.com/JZP018/vuln03/blob/main/linksys/E5600/CI_InternetConnection/CI_InternetConnection.pdf");
  script_xref(name:"URL", value:"https://github.com/JZP018/vuln03/blob/main/linksys/E5600/CI_ddnsStatus_DynDNS_mailex/CI_ddnsStatus_DynDNS_mailex.pdf");
  script_xref(name:"URL", value:"https://github.com/JZP018/vuln03/blob/main/linksys/E5600/CI_ddnsStatus_DynDNS_hostname/CI_ddnsStatus_DynDNS_hostname.pdf");
  script_xref(name:"URL", value:"https://github.com/JZP018/vuln03/blob/main/linksys/E5600/CI_ddnsStatus_DynDNS_password/CI_ddnsStatus_DynDNS_password.pdf");
  script_xref(name:"URL", value:"https://github.com/JZP018/vuln03/blob/main/linksys/E5600/CI_ddnsStatus_DynDNS_username/CI_ddnsStatus_DynDNS_username.pdf");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE ) )
  exit( 0 );

vers = infos["version"];
path = infos["location"];

if( version_is_less_equal( version:vers, test_version:"1.1.0.26" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"None", install_path:path );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 0 );
