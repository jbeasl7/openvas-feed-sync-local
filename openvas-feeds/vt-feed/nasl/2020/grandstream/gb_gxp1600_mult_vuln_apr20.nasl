# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143707");
  script_version("2026-02-24T05:57:09+0000");
  script_tag(name:"last_modification", value:"2026-02-24 05:57:09 +0000 (Tue, 24 Feb 2026)");
  script_tag(name:"creation_date", value:"2020-04-15 08:54:43 +0000 (Wed, 15 Apr 2020)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-04-14 17:54:00 +0000 (Tue, 14 Apr 2020)");

  script_cve_id("CVE-2020-5738", "CVE-2020-5739");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Grandstream GXP1600 Series IP Phones <= 1.0.4.152 Multiple RCE Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("General");
  script_dependencies("gb_grandstream_gxp_consolidation.nasl");
  script_mandatory_keys("grandstream/gxp/detected");

  script_tag(name:"summary", value:"Grandstream GXP1600 Series IP Phones are prone to multiple
  remote code execution (RCE) vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2020-5738: Authenticated RCE via Tar Upload

  - CVE-2020-5739: Authenticated RCE via OpenVPN Configuration File");

  script_tag(name:"affected", value:"Grandstream GXP1600 Series IP Phones with firmware version
  1.0.4.152 and probably prior.");

  script_tag(name:"solution", value:"Update to version 1.0.5.3 or later.");

  script_xref(name:"URL", value:"https://medium.com/tenable-techblog/reverse-shell-from-an-openvpn-configuration-file-73fd8b1d38da");
  script_xref(name:"URL", value:"https://www.tenable.com/security/research/tra-2020-22");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/o:grandstream:gxp1610_firmware",
                     "cpe:/o:grandstream:gxp1615_firmware",
                     "cpe:/o:grandstream:gxp1620_firmware",
                     "cpe:/o:grandstream:gxp1625_firmware",
                     "cpe:/o:grandstream:gxp1628_firmware",
                     "cpe:/o:grandstream:gxp1630_firmware");

if (!infos = get_app_version_from_list(cpe_list: cpe_list, nofork: TRUE))
  exit(0);

vers = infos["version"];

if (version_is_less_equal(version: vers, test_version: "1.0.4.152")) {
  report = report_fixed_ver(installed_version: vers, fixed_version: "1.0.5.3");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
