# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142167");
  script_version("2024-08-14T05:05:52+0000");
  script_tag(name:"last_modification", value:"2024-08-14 05:05:52 +0000 (Wed, 14 Aug 2024)");
  script_tag(name:"creation_date", value:"2019-03-26 10:13:52 +0000 (Tue, 26 Mar 2019)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("D-Link DNS Devices Cr1ptT0r Ransomware");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("General");
  script_dependencies("gb_dlink_dns_http_detect.nasl");
  script_mandatory_keys("d-link/dns/detected");

  script_tag(name:"summary", value:"Multiple D-Link DNS devices are prone to some unknown attacks
  which are actively exploited e.g. by the ransomeware Cr1ptT0r.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Cr1ptT0r ransomware encrypt stored information and then demands
  payment to decrypt the information. Other impact might be possible too.");

  script_tag(name:"affected", value:"D-Link DNS-320, DNS-325, DNS-320L and DNS-327L.");

  script_tag(name:"solution", value:"Updated firmware are provided for DNS-320L and DNS-327L. Please
  see the referenced vendor advisory for other solutions.");

  script_xref(name:"URL", value:"https://www.bleepingcomputer.com/news/security/cr1ptt0r-ransomware-infects-d-link-nas-devices-targets-embedded-systems/");
  script_xref(name:"URL", value:"https://securityadvisories.dlink.com/announcement/publication.aspx?name=SAP10110");
  script_xref(name:"URL", value:"ftp://ftp2.dlink.com/SECURITY_ADVISEMENTS/DNS-320/REVA/DNS-320_REVA_RELEASE_NOTES_v2.06B01.pdf");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/o:dlink:dns-320_firmware",
                     "cpe:/o:dlink:dns-320l_firmware",
                     "cpe:/o:dlink:dns-325_firmware",
                     "cpe:/o:dlink:dns-327l_firmware");

if (!infos = get_app_version_from_list(cpe_list: cpe_list, nofork: TRUE))
  exit(0);

cpe = infos["cpe"];
version = infos["version"];

if (cpe == "cpe:/o:dlink:dns-320_firmware") {
  if (version_is_less(version: version, test_version: "2.06b01")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2.06B01");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:dlink:dns-320l_firmware") {
  if (version_is_less(version: version, test_version: "1.11")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "1.11");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:dlink:dns-325_firmware") {
  report = report_fixed_ver(installed_version: version, fixed_version: "None");
  security_message(port: 0, data: report);
  exit(0);
}

if (cpe == "cpe:/o:dlink:dns-327l_firmware") {
  if (version_is_less(version: version, test_version: "1.10")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "1.10");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
