# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.171563");
  script_version("2025-07-01T05:42:02+0000");
  script_tag(name:"last_modification", value:"2025-07-01 05:42:02 +0000 (Tue, 01 Jul 2025)");
  script_tag(name:"creation_date", value:"2025-06-27 20:20:13 +0000 (Fri, 27 Jun 2025)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-06-06 18:48:46 +0000 (Fri, 06 Jun 2025)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_cve_id("CVE-2021-41503", "CVE-2021-41504", "CVE-2024-37606", "CVE-2025-4841",
                "CVE-2025-4842", "CVE-2025-4843", "CVE-2025-5571", "CVE-2025-5572",
                "CVE-2025-5573");

  script_name("D-Link Multiple DCS IP Camera Devices Multiple Vulnerabilities (SAP10247)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_dlink_dcs_consolidation.nasl");
  script_mandatory_keys("d-link/dcs/detected");

  script_tag(name:"summary", value:"Multiple D-Link DCS IP camera devices are prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if the target host is a vulnerable device.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2021-41503: The use of the basic authentication for the devices command interface allows
  attack vectors that may compromise the cameras configuration and allow malicious users on the
  LAN to access the device

  - CVE-2021-41504: The use of the digest-authentication for the devices command interface may
  allow further attack vectors that may compromise the cameras configuration and allow malicious
  users on the LAN to access the device.

  - CVE-2024-37606: A Stack overflow vulnerability allows attackers to cause a Denial of Service
  (DoS) via a crafted HTTP request.

  - CVE-2025-4841, CVE-2025-4842, CVE-2025-4843: Stack-based buffer overflow

  - CVE-2025-5571, CVE-2025-5572, CVE-2025-5573: OS Command injection");

  script_tag(name:"affected", value:"D-Link DCS-930L, DCS-931L, DCS-932L, DCS-933L, DCS-934L,
  DCS-935L, DCS-936L, DCS-940L, DCS-942L, DCS-960L and DCS-5000L devices in all versions.");

  script_tag(name:"solution", value:"No solution was made available by the vendor. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.

  Note: The vendor states that technical support for the devices has ended between 2015 and 2023,
  therefore most probably no effort will be made to provide a fix for these vulnerabilities.");

  script_xref(name:"URL", value:"https://supportannouncement.us.dlink.com/security/publication.aspx?name=SAP10247");
  script_xref(name:"URL", value:"https://kth.diva-portal.org/smash/get/diva2:1619459/FULLTEXT01.pdf");
  script_xref(name:"URL", value:"https://github.com/BeaCox/IoT_vuln/tree/main/D-Link/DCS-932L/gpio_bof");
  script_xref(name:"URL", value:"https://github.com/BeaCox/IoT_vuln/tree/main/D-Link/DCS-932L/ucp_bof");
  script_xref(name:"URL", value:"https://github.com/BeaCox/IoT_vuln/tree/main/D-Link/DCS-932L/udev_bof");
  script_xref(name:"URL", value:"https://github.com/wudipjq/my_vuln/blob/main/D-Link5/vuln_42/42.md");
  script_xref(name:"URL", value:"https://github.com/wudipjq/my_vuln/blob/main/D-Link5/vuln_43/43.md");
  script_xref(name:"URL", value:"https://github.com/wudipjq/my_vuln/blob/main/D-Link5/vuln_44/44.md");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list( "cpe:/o:dlink:dcs-930l_firmware",
                      "cpe:/o:dlink:dcs-930lb1_firmware",
                      "cpe:/o:dlink:dcs-931l_firmware",
                      "cpe:/o:dlink:dcs-932l_firmware",
                      "cpe:/o:dlink:dcs-932lb1_firmware",
                      "cpe:/o:dlink:dcs-933l_firmware",
                      "cpe:/o:dlink:dcs-934l_firmware",
                      "cpe:/o:dlink:dcs-935l_firmware",
                      "cpe:/o:dlink:dcs-936l_firmware",
                      "cpe:/o:dlink:dcs-940l_firmware",
                      "cpe:/o:dlink:dcs-942l_firmware",
                      "cpe:/o:dlink:dcs-960l_firmware",
                      "cpe:/o:dlink:dcs-5000l_firmware" );

if ( ! infos = get_app_version_from_list( cpe_list:cpe_list, nofork:TRUE ) )
  exit( 0 );

version = infos["version"];

report = report_fixed_ver( installed_version:version, fixed_version:"None" );
security_message( port:0, data:report );
exit( 0 );