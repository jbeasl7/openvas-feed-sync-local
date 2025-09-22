# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:dlink:dir-816_firmware";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.171142");
  script_version("2025-06-25T05:41:02+0000");
  script_tag(name:"last_modification", value:"2025-06-25 05:41:02 +0000 (Wed, 25 Jun 2025)");
  script_tag(name:"creation_date", value:"2025-01-31 09:50:47 +0000 (Fri, 31 Jan 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-06-05 03:15:27 +0000 (Thu, 05 Jun 2025)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"WillNotFix");

  # nb: Unlike other VTs we're using the CVEs line by line here for easier addition of new CVEs / to
  #     avoid too large diffs when adding a new CVE.
  script_cve_id("CVE-2023-24331",
                "CVE-2023-39637",
                "CVE-2023-43236",
                "CVE-2023-43237",
                "CVE-2023-43238",
                "CVE-2023-43239",
                "CVE-2023-43240",
                "CVE-2024-13102",
                "CVE-2024-13103",
                "CVE-2024-13104",
                "CVE-2024-13105",
                "CVE-2024-13106",
                "CVE-2024-13107",
                "CVE-2024-13108",
                "CVE-2024-57676",
                "CVE-2024-57677",
                "CVE-2024-57678",
                "CVE-2024-57679",
                "CVE-2024-57680",
                "CVE-2024-57681",
                "CVE-2024-57682",
                "CVE-2024-57683",
                "CVE-2024-57684",
                "CVE-2025-5620",
                "CVE-2025-5621",
                "CVE-2025-5622",
                "CVE-2025-5623",
                "CVE-2025-5624",
                "CVE-2025-5630",
                "CVE-2025-44835"
               );

  script_name("D-Link DIR-816 Devices Multiple Vulnerabilities (2023 - 2025)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("General");
  script_dependencies("gb_dlink_dir_consolidation.nasl");
  script_mandatory_keys("d-link/dir/detected");

  script_tag(name:"summary", value:"D-Link DIR-816 devices are prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if the target host is a vulnerable device.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2023-24331: Command injection

  - CVE-2023-39637: Command injection vulnerability via the component /goform/Diagnosis

  - CVE-2023-43236, CVE-2023-43237, CVE-2023-43238, CVE-2023-43239, CVE-2023-43240: Multiple stack
  overflow vulnerabilities

  - CVE-2024-13102: Improper access control in /goform/DDNS

  - CVE-2024-13103: Improper access control in the /goform/form2AddVrtsrv.cgi file of the component
  Virtual Service Handler

  - CVE-2024-13104: Improper access control in the /goform/form2AdvanceSetup.cgi file of the
  component WiFi Settings Handler

  - CVE-2024-13105: Improper access control in the /goform/form2Dhcpd.cgi file of the component
  DHCPD Setting Handler

  - CVE-2024-13106: Improper access control in the /goform/form2IPQoSTcAdd file of the component
  IP QoS Handler

  - CVE-2024-13107: Improper access control in the /goform/form2LocalAclEditcfg.cgi file of the
  component ACL Handler

  - CVE-2024-13108: Improper access control in the /goform/form2NetSniper.cgi file

  - CVE-2024-57676, CVE-2024-57677, CVE-2024-57678, CVE-2024-57679, CVE-2024-57680, CVE-2024-57681,
  CVE-2024-57682, CVE-2024-57683, CVE-2024-57684: Access control issues in various components

  - CVE-2025-5620, CVE-2025-5621: OS command injection

  - CVE-2025-5622, CVE-2025-5623, CVE-2025-5624, CVE-2025-5630: Stack-based buffer overflow

  - CVE-2025-44835: Command injection in iptablesWebsFilterRun");

  script_tag(name:"affected", value:"D-Link DIR-816 devices in all versions.");

  script_tag(name:"solution", value:"No solution was made available by the vendor. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.

  Note: Vendor states that DIR-816 reached its End-of-Support Date in 30.04.2023, it is no longer
  supported, and firmware development has ceased. See vendor advisory for further
  recommendations.");

  script_xref(name:"URL", value:"https://github.com/caoyebo/CVE/tree/main/Dlink%20816%20-%20CVE-2023-24331");
  script_xref(name:"URL", value:"https://github.com/peris-navince/founded-0-days/tree/main/Dlink/816");
  script_xref(name:"URL", value:"https://github.com/wudipjq/my_vuln/blob/main/D-Link5/vuln_48/48.md");
  script_xref(name:"URL", value:"https://github.com/wudipjq/my_vuln/blob/main/D-Link5/vuln_49/49.md");
  script_xref(name:"URL", value:"https://github.com/wudipjq/my_vuln/blob/main/D-Link5/vuln_50/50.md");
  script_xref(name:"URL", value:"https://github.com/wudipjq/my_vuln/blob/main/D-Link5/vuln_51/51.md");
  script_xref(name:"URL", value:"https://github.com/wudipjq/my_vuln/blob/main/D-Link5/vuln_53/53.md");
  script_xref(name:"URL", value:"https://github.com/wudipjq/my_vuln/blob/main/D-Link5/vuln_54/54.md");
  script_xref(name:"URL", value:"https://service.dlink.co.in/resources/EOL-Products-Without-Service.pdf");
  script_xref(name:"URL", value:"https://legacy.us.dlink.com/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE, nofork:TRUE ) )
  exit( 0 );

report = report_fixed_ver( installed_version:version, fixed_version:"None" );
security_message( port:0, data:report );
exit( 0 );
