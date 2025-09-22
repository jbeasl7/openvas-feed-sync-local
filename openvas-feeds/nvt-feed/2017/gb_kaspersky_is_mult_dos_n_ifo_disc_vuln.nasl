# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:kaspersky_lab:kaspersky_internet_security";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810514");
  script_version("2023-07-25T05:05:58+0000");
  script_cve_id("CVE-2016-4329", "CVE-2016-4305", "CVE-2016-4306", "CVE-2016-4307",
                "CVE-2016-4304");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-01-11 02:59:00 +0000 (Wed, 11 Jan 2017)");
  script_tag(name:"creation_date", value:"2017-01-23 14:29:52 +0530 (Mon, 23 Jan 2017)");
  script_name("Kaspersky Internet Security < 17.0.0.611 Multiple Vulnerabilities");

  script_tag(name:"summary", value:"Kaspersky Internet Security is prone to multiple denial of
  service (DoS) and information disclosure vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - An error in the 'syscall filtering' functionality of 'KLIF driver'.

  - An error in the 'IOCTL handling' functionality 'KL1 driver'.

  - An error in various 'IOCTL handlers' of the 'KLDISK driver'. Specially crafted IOCTL requests
  can cause the driver to return out-of-bounds kernel memory.

  - An error in 'window broadcast message handling' functionality.");

  script_tag(name:"impact", value:"Successful exploitation would allow remote attackers to cause
  application termination, bypass protection mechanism and obtain sensitive information.");

  script_tag(name:"affected", value:"Kaspersky Internet Security version 16.0.0.614 and prior.");

  script_tag(name:"solution", value:"Update to version 17.0.0.611 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://support.kaspersky.com/vulnerability.aspx?el=12430#250816_1");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/92771");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/92639");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/92657");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/92683");
  script_xref(name:"URL", value:"http://securitytracker.com/id/1036702");
  script_xref(name:"URL", value:"http://www.talosintelligence.com/reports/TALOS-2016-0175");

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_kaspersky_av_detect.nasl");
  script_mandatory_keys("Kaspersky/IntNetSec/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!vers = get_app_version(cpe:CPE))
  exit(0);

if(version_is_less_equal(version:vers, test_version:"16.0.0.614")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"17.0.0.611");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);