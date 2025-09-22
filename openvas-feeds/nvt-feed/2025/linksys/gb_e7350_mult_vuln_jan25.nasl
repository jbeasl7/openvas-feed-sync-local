# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:linksys:e7350_firmware";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.125114");
  script_version("2025-01-22T05:38:11+0000");
  script_tag(name:"last_modification", value:"2025-01-22 05:38:11 +0000 (Wed, 22 Jan 2025)");
  script_tag(name:"creation_date", value:"2025-01-16 15:11:08 +0000 (Thu, 16 Jan 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2024-57222", "CVE-2024-57223", "CVE-2024-57224", "CVE-2024-57225",
                "CVE-2024-57226", "CVE-2024-57227", "CVE-2024-57228");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_name("Linksys E7350 Router <= 1.1.00.032 Multiple Command Injection Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_linksys_devices_consolidation.nasl");
  script_mandatory_keys("linksys/detected");

  script_tag(name:"summary", value:"Linksys E7350 routers are prone to multiple command injection
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2024-57222: Command injection vulnerability via the ifname parameter in the apcli_cancel_wp
    function

  - CVE-2024-57223: Command injection vulnerability via the ifname parameter in the
    apcli_wps_gen_pincode function

  - CVE-2024-57224: Command injection vulnerability via the ifname parameter in the
    apcli_do_enr_pin_wps function

  - CVE-2024-57225: Command injection vulnerability via the devname parameter in the reset_wifi
    function

  - CVE-2024-57226: Command injection vulnerability via the iface parameter in the
    vif_enable function

  - CVE-2024-57227: Command injection vulnerability via the ifname parameter in the
    apcli_do_enr_pbc_wps function

  - CVE-2024-57228: Command injection vulnerability via the iface parameter in the vif_disable
    function.");

  script_tag(name:"affected", value:"Linksys E7350 routers with firmware versions 1.1.00.032 and
  prior.");

  script_tag(name:"solution", value:"No known solution is available as of 16th January, 2025.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://github.com/yanggao017/vuln/blob/main/Linksys/E7350/CI_5_apcli_cancel_wps/README.md");
  script_xref(name:"URL", value:"https://github.com/yanggao017/vuln/blob/main/Linksys/E7350/CI_6_apcli_wps_gen_pincode/README.md");
  script_xref(name:"URL", value:"https://github.com/yanggao017/vuln/blob/main/Linksys/E7350/CI_3_apcli_do_enr_pin_wps/README.md");
  script_xref(name:"URL", value:"https://github.com/yanggao017/vuln/blob/main/Linksys/E7350/CI_7_reset_wifi/README.md");
  script_xref(name:"URL", value:"https://github.com/yanggao017/vuln/blob/main/Linksys/E7350/CI_2_vif_enable/README.md");
  script_xref(name:"URL", value:"https://github.com/yanggao017/vuln/blob/main/Linksys/E7350/CI_4_apcli_do_enr_pbc_wps/README.md");
  script_xref(name:"URL", value:"https://github.com/yanggao017/vuln/blob/main/Linksys/E7350/CI_1_vif_disable/README.md");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE ) )
  exit( 0 );

vers = infos["version"];
path = infos["location"];

if( version_is_less_equal( version:vers, test_version:"1.1.00.032" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"None", install_path:path );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 0 );
