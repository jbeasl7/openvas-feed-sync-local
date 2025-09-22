# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:linksys:e5600_firmware";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.125115");
  script_version("2025-05-15T05:40:37+0000");
  script_tag(name:"last_modification", value:"2025-05-15 05:40:37 +0000 (Thu, 15 May 2025)");
  script_tag(name:"creation_date", value:"2025-01-17 13:10:13 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"cvss_base", value:"4.1");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:S/C:P/I:P/A:N");

  script_cve_id("CVE-2025-22996", "CVE-2025-22997", "CVE-2025-29223", "CVE-2025-29226",
                "CVE-2025-29227", "CVE-2025-29230");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_name("Linksys E5600 Router <= 1.1.0.26 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_linksys_devices_consolidation.nasl");
  script_mandatory_keys("linksys/detected");

  script_tag(name:"summary", value:"Linksys E5600 routers are prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2025-22996: A stored cross-site scripting (XSS) vulnerability in the spf_table_content
  component allows attackers to execute arbitrary web scripts or HTML via a crafted payload
  injected into the desc parameter.

  - CVE-2025-22997: A stored cross-site scripting (XSS) vulnerability in the prf_table_content
  component allows attackers to execute arbitrary web scripts or HTML via a crafted payload
  injected into the desc parameter.

  - CVE-2025-29223: Command injection vulnerability via the pt parameter in the traceRoute
  function

  - CVE-2025-29226: The \usr\share\lua\runtime.lua file contains a command injection vulnerability
  in the runtime.pingTest function via the pt['count'] parameter.

  - CVE-2025-29227: The \usr\share\lua\runtime.lua file contains a command injection vulnerability
  in the runtime.pingTest function via the pt['pkgsize'] parameter.

  - CVE-2025-29230: Command injection vulnerability in the runtime.emailReg function that can be
  triggered via the pt['email'] parameter.");

  script_tag(name:"affected", value:"Linksys E5600 routers with firmware versions 1.1.0.26 and
  prior.");

  script_tag(name:"solution", value:"No known solution is available as of 17th January, 2025.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://github.com/SunnyYANGyaya/firmcrosser/blob/main/Linksys/E5600-2.md");
  script_xref(name:"URL", value:"https://github.com/SunnyYANGyaya/firmcrosser/blob/main/Linksys/E5600-1.md");
  script_xref(name:"URL", value:"https://github.com/JZP018/Vuln/blob/main/linsys/E5600/CI_traceRoute/CI_traceRoute.md");
  script_xref(name:"URL", value:"https://github.com/JZP018/Vuln/blob/main/linsys/E5600/CI_pingTest_count/CI_pingTest_count.md");
  script_xref(name:"URL", value:"https://github.com/JZP018/Vuln/blob/main/linsys/E5600/CI_pingTest_pkgsize/CI_pingTest_pkgsize.md");
  script_xref(name:"URL", value:"https://github.com/JZP018/Vuln/blob/main/linsys/E5600/CI_emailReg_email/CI_emailReg_email.md");

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
