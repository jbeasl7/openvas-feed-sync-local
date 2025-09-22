# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140187");
  script_version("2025-01-31T15:39:24+0000");
  script_tag(name:"last_modification", value:"2025-01-31 15:39:24 +0000 (Fri, 31 Jan 2025)");
  script_tag(name:"creation_date", value:"2017-03-14 17:34:31 +0100 (Tue, 14 Mar 2017)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-05-11 13:25:00 +0000 (Tue, 11 May 2021)");

  script_cve_id("CVE-2017-5859");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Cambium Networks cnPilot R200/201 RSA Keys Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("General");
  script_dependencies("gb_cambium_cnpilot_consolidation.nasl");
  script_mandatory_keys("cambium/cnpilot/detected");

  script_tag(name:"summary", value:"On Cambium Networks cnPilot R200/201 devices before 4.3, there
  is a vulnerability involving the certificate of the device and its RSA keys, aka RBN-183.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"cnPilot R200/201 devices prior to firmware version 4.3.");

  script_tag(name:"solution", value:"Update to version 4.3 or later.");

  script_xref(name:"URL", value:"https://support.cambiumnetworks.com/file/3f88842a39f37b0d4ce5d43e5aa21bf1c4f9f1ca");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/o:cambiumnetworks:cnpilot_r200_firmware",
                     "cpe:/o:cambiumnetworks:cnpilot_r201_firmware");

if (!infos = get_app_version_from_list(cpe_list: cpe_list, nofork: TRUE))
  exit(0);

version = infos["version"];

if (version_is_less(version: version, test_version: "4.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.3");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
