# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE_PREFIX = "cpe:/o:lexmark:";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.153884");
  script_version("2025-06-05T05:40:56+0000");
  script_tag(name:"last_modification", value:"2025-06-05 05:40:56 +0000 (Thu, 05 Jun 2025)");
  script_tag(name:"creation_date", value:"2025-01-28 03:47:05 +0000 (Tue, 28 Jan 2025)");
  script_tag(name:"cvss_base", value:"4.7");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:M/C:P/I:P/A:P");

  script_cve_id("CVE-2023-50738");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Lexmark Printer Firmware Downgrade Prevention Vulnerability (CVE-2023-50738)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("General");
  script_dependencies("gb_lexmark_printer_consolidation.nasl");
  script_mandatory_keys("lexmark_printer/detected");

  script_tag(name:"summary", value:"Multiple Lexmark printer devices are prone to a firmware
  downgrade prevention vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable firmware version is present on the
  target host.");

  script_tag(name:"insight", value:"A new feature to prevent Firmware downgrades was recently added
  to some Lexmark products. A method to override this downgrade protection has been identified.");

  script_tag(name:"impact", value:"Successful exploitation of this vulnerability can lead to an
  attacker being able to remotely execute arbitrary code on a device.");

  script_tag(name:"solution", value:"See the referenced vendor advisories for a solution.");

  script_xref(name:"URL", value:"https://publications.lexmark.com/publications/security-alerts/CVE-2023-50738.pdf");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!infos = get_app_port_from_cpe_prefix(cpe: CPE_PREFIX, first_cpe_only: TRUE))
  exit(0);

port = infos["port"];
cpe = infos["cpe"];

if (!version = toupper(get_app_version(cpe: cpe, port: port, nofork: TRUE)))
  exit(0);

if (cpe =~ "^cpe:/o:lexmark:cx93[01]" || cpe =~ "^cpe:/o:lexmark:cx94[234]" ||
    cpe =~ "^cpe:/o:lexmark:xc93[23]5" || cpe =~ "^cpe:/o:lexmark:xc94[56]5") {
  if (version_is_less(version: version, test_version: "CXTPC.230.042")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CXTPC.230.042");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "CXTPC.230.075", test_version2: "CXTPC.230.086")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CXTPC.230.087");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "CXTPC.230.100", test_version2: "CXTPC.230.104")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CXTPC.230.105");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "CXTPC.230.200", test_version2: "CXTPC.230.209")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CXTPC.230.210");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:cs943") {
  if (version_is_less(version: version, test_version: "CSTPC.230.042")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CSTPC.230.042");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "CSTPC.230.075", test_version2: "CSTPC.230.086")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CSTPC.230.087");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "CSTPC.230.100", test_version2: "CSTPC.230.104")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CSTPC.230.105");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "CSTPC.230.200", test_version2: "CSTPC.230.209")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CSTPC.230.210");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:mx432" || cpe =~ "^cpe:/o:lexmark:xm3142") {
  if (version_is_less(version: version, test_version: "MXTCT.230.042")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MXTCT.230.042");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "MXTCT.230.075", test_version2: "MXTCT.230.086")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MXTCT.230.087");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "MXTCT.230.100", test_version2: "MXTCT.230.104")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MXTCT.230.105");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "MXTCT.230.200", test_version2: "MXTCT.230.209")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MXTCT.230.210");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:mx931") {
  if (version_is_less(version: version, test_version: "MXTPM.230.042")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MXTPM.230.042");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "MXTPM.230.075", test_version2: "MXTPM.230.086")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MXTCT.230.087");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "MXTPM.230.100", test_version2: "MXTPM.230.101")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MXTPM.230.105");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "MXTPM.230.200", test_version2: "MXTPM.230.209")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MXTPM.230.210");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:cx73[057]" || cpe =~ "^cpe:/o:lexmark:xc43[45]2") {
  if (version_is_less(version: version, test_version: "CXTMM.230.042")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CXTMM.230.042");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "CXTMM.230.075", test_version2: "CXTMM.230.086")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CXTMM.230.087");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "CXTMM.230.100", test_version2: "CXTMM.230.104")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CXTMM.230.105");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "CXTMM.230.200", test_version2: "CXTMM.230.209")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CXTMM.230.210");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:cs73[057]" || cpe =~ "^cpe:/o:lexmark:c43[45]2") {
  if (version_is_less(version: version, test_version: "CSTMM.230.042")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CSTMM.230.042");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "CSTMM.230.075", test_version2: "CSTMM.230.086")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CSTMM.230.087");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "CSTMM.230.100", test_version2: "CSTMM.230.104")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CSTMM.230.105");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "CSTMM.230.200", test_version2: "CSTMM.230.209")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CSTMM.230.210");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:b2236") {
  if (version_is_less(version: version, test_version: "MSLSG.230.042")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MSLSG.230.042");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "MSLSG.230.075", test_version2: "MSLSG.230.086")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MSLSG.230.087");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "MSLSG.230.100", test_version2: "MSLSG.230.104")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MSLSG.230.105");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "MSLSG.230.200", test_version2: "MSLSG.230.209")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MSLSG.230.210");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:mb2236") {
  if (version_is_less(version: version, test_version: "MXLSG.230.042")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MXLSG.230.042");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "MXLSG.230.075", test_version2: "MXLSG.230.086")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MXLSG.230.087");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "MXLSG.230.100", test_version2: "MXLSG.230.104")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MXLSG.230.105");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "MXLSG.230.200", test_version2: "MXLSG.230.209")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MXLSG.230.210");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:ms[34]31" || cpe =~ "^cpe:/o:lexmark:ms439" ||
    cpe =~ "^cpe:/o:lexmark:m1342" || cpe =~ "^cpe:/o:lexmark:b3442" ||
    cpe =~ "^cpe:/o:lexmark:b3340") {
  if (version_is_less(version: version, test_version: "MSLBD.230.042")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MSLBD.230.042");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "MSLBD.230.075", test_version2: "MSLBD.230.086")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MSLBD.230.087");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "MSLBD.230.100", test_version2: "MSLBD.230.104")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MSLBD.230.105");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "MSLBD.230.200", test_version2: "MSLBD.230.209")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MSLBD.230.210");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:xm1342" || cpe =~ "^cpe:/o:lexmark:mx[34]31" ||
    cpe =~ "^cpe:/o:lexmark:mb3442") {
  if (version_is_less(version: version, test_version: "MXLBD.230.042")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MXLBD.230.042");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "MXLBD.230.075", test_version2: "MXLBD.230.086")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MXLBD.230.087");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "MXLBD.230.100", test_version2: "MXLBD.230.104")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MXLBD.230.105");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "MXLBD.230.200", test_version2: "MXLBD.230.209")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MXLBD.230.210");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:ms[3456]21" || cpe =~ "^cpe:/o:lexmark:m124[26]" ||
    cpe =~ "^cpe:/o:lexmark:b2338" || cpe =~ "^cpe:/o:lexmark:b2442" ||
    cpe =~ "^cpe:/o:lexmark:b2546" || cpe =~ "^cpe:/o:lexmark:b2650") {
  if (version_is_less(version: version, test_version: "MSNGM.230.042")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MSNGM.230.042");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "MSNGM.230.075", test_version2: "MSNGM.230.086")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MSNGM.230.087");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "MSNGM.230.100", test_version2: "MSNGM.230.104")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MSNGM.230.105");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "MSNGM.230.200", test_version2: "MSNGM.230.209")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MSNGM.230.210");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:ms622" || cpe =~ "^cpe:/o:lexmark:m3250") {
  if (version_is_less(version: version, test_version: "MSTGM.230.042")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MSTGM.230.042");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "MSTGM.230.075", test_version2: "MSTGM.230.086")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MSTGM.230.087");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "MSTGM.230.100", test_version2: "MSTGM.230.104")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MSTGM.230.105");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "MSTGM.230.200", test_version2: "MSTGM.230.209")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MSTGM.230.210");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:mx321" || cpe =~ "^cpe:/o:lexmark:mb2338") {
  if (version_is_less(version: version, test_version: "MXNGM.230.042")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MXNGM.230.042");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "MXNGM.230.075", test_version2: "MXNGM.230.086")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MXNGM.230.087");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "MXNGM.230.100", test_version2: "MXNGM.230.104")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MXNGM.230.105");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "MXNGM.230.200", test_version2: "MXNGM.230.209")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MXNGM.230.210");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:mx[45]21" || cpe =~ "^cpe:/o:lexmark:mx[56]22" ||
    cpe =~ "^cpe:/o:lexmark:xm124[26]" || cpe =~ "^cpe:/o:lexmark:xm3250" ||
    cpe =~ "^cpe:/o:lexmark:mb2442" || cpe =~ "^cpe:/o:lexmark:mb2546" ||
    cpe =~ "^cpe:/o:lexmark:mb2650") {
  if (version_is_less(version: version, test_version: "MXTGM.230.042")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MXTGM.230.042");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "MXTGM.230.075", test_version2: "MXTGM.230.086")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MXTGM.230.087");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "MXTGM.230.100", test_version2: "MXTGM.230.104")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MXTGM.230.105");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "MXTGM.230.200", test_version2: "MXTGM.230.209")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MXTGM.230.210");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:ms[78]25" || cpe =~ "^cpe:/o:lexmark:ms82[13]" ||
    cpe =~ "^cpe:/o:lexmark:b2865") {
  if (version_is_less(version: version, test_version: "MSNGW.230.042")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MSNGW.230.042");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "MSNGW.230.075", test_version2: "MSNGW.230.086")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MSNGW.230.087");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "MSNGW.230.100", test_version2: "MSNGW.230.104")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MSNGW.230.105");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "MSNGW.230.200", test_version2: "MSNGW.230.209")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MSNGW.230.210");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:ms82[26]" || cpe =~ "^cpe:/o:lexmark:m5255" ||
    cpe =~ "^cpe:/o:lexmark:m5270") {
  if (version_is_less(version: version, test_version: "MSTGW.230.042")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MSTGW.230.042");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "MSTGW.230.075", test_version2: "MSTGW.230.086")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MSTGW.230.087");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "MSTGW.230.100", test_version2: "MSTGW.230.104")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MSTGW.230.105");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "MSTGW.230.200", test_version2: "MSTGW.230.209")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MSTGW.230.210");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:mx72[125]" || cpe =~ "^cpe:/o:lexmark:mx82[26]" ||
    cpe =~ "^cpe:/o:lexmark:xm53(65|70)" || cpe =~ "^cpe:/o:lexmark:xm73(55|70)" ||
    cpe =~ "^cpe:/o:lexmark:mb2770") {
  if (version_is_less(version: version, test_version: "MXTGW.230.042")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MXTGW.230.042");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "MXTGW.230.075", test_version2: "MXTGW.230.086")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MXTGW.230.087");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "MXTGW.230.100", test_version2: "MXTGW.230.104")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MXTGW.230.105");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "MXTGW.230.200", test_version2: "MXTGW.230.209")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MXTGW.230.210");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:c3426" || cpe =~ "^cpe:/o:lexmark:cs43[19]" ||
    cpe =~ "^cpe:/o:lexmark:c2326") {
  if (version_is_less(version: version, test_version: "CSLBN.230.042")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CSLBN.230.042");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "CSLBN.230.075", test_version2: "CSLBN.230.086")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CSLBN.230.087");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "CSLBN.230.100", test_version2: "CSLBN.230.104")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CSLBN.230.105");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "CSLBN.230.200", test_version2: "CSLBN.230.209")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CSLBN.230.210");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:cs331" || cpe =~ "^cpe:/o:lexmark:c3224" ||
    cpe =~ "^cpe:/o:lexmark:c3326") {
  if (version_is_less(version: version, test_version: "CSLBL.230.042")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CSLBL.230.042");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "CSLBL.230.075", test_version2: "CSLBL.230.086")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CSLBL.230.087");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "CSLBL.230.100", test_version2: "CSLBL.230.104")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CSLBL.230.105");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "CSLBL.230.200", test_version2: "CSLBL.230.209")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CSLBL.230.210");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:mc3426" || cpe =~ "^cpe:/o:lexmark:cx431" ||
    cpe =~ "^cpe:/o:lexmark:xc2326") {
  if (version_is_less(version: version, test_version: "CXLBN.230.042")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CXLBN.230.042");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "CXLBN.230.075", test_version2: "CXLBN.230.086")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CXLBN.230.087");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "CXLBN.230.100", test_version2: "CXLBN.230.104")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CXLBN.230.105");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "CXLBN.230.200", test_version2: "CXLBN.230.209")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CXLBN.230.210");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:mc3224" || cpe =~ "^cpe:/o:lexmark:mc3326" ||
    cpe =~ "^cpe:/o:lexmark:cx331") {
  if (version_is_less(version: version, test_version: "CXLBL.230.042")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CXLBL.230.042");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "CXLBL.230.075", test_version2: "CXLBL.230.086")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CXLBL.230.087");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "CXLBL.230.100", test_version2: "CXLBL.230.104")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CXLBL.230.105");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "CXLBL.230.200", test_version2: "CXLBL.230.209")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CXLBL.230.210");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:cs622" || cpe =~ "^cpe:/o:lexmark:c2240") {
  if (version_is_less(version: version, test_version: "CSTZJ.230.042")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CSTZJ.230.042");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "CSTZJ.230.075", test_version2: "CSTZJ.230.086")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CSTZJ.230.087");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "CSTZJ.230.100", test_version2: "CSTZJ.230.104")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CSTZJ.230.105");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "CSTZJ.230.200", test_version2: "CSTZJ.230.209")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CSTZJ.230.210");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:cs[45]21" || cpe =~ "^cpe:/o:lexmark:c2[34]25" ||
    cpe =~ "^cpe:/o:lexmark:c2535") {
  if (version_is_less(version: version, test_version: "CSNZJ.230.042")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CSNZJ.230.042");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "CSNZJ.230.075", test_version2: "CSNZJ.230.086")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CSNZJ.230.087");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "CSNZJ.230.100", test_version2: "CSNZJ.230.104")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CSNZJ.230.105");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "CSNZJ.230.200", test_version2: "CSNZJ.230.209")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CSNZJ.230.210");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:cx[56]22" || cpe =~ "^cpe:/o:lexmark:cx625" ||
    cpe =~ "^cpe:/o:lexmark:xc2235" || cpe =~ "^cpe:/o:lexmark:xc4240" ||
    cpe =~ "^cpe:/o:lexmark:mc2535" || cpe =~ "^cpe:/o:lexmark:mc2640") {
  if (version_is_less(version: version, test_version: "CXTZJ.230.042")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CXTZJ.230.042");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "CXTZJ.230.075", test_version2: "CXTZJ.230.086")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CXTZJ.230.087");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "CXTZJ.230.100", test_version2: "CXTZJ.230.104")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CXTZJ.230.105");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "CXTZJ.230.200", test_version2: "CXTZJ.230.209")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CXTZJ.230.210");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:cx421" || cpe =~ "^cpe:/o:lexmark:mc2[34]25") {
  if (version_is_less(version: version, test_version: "CXNZJ.230.042")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CXNZJ.230.042");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "CXNZJ.230.075", test_version2: "CXNZJ.230.086")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CXNZJ.230.087");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "CXNZJ.230.100", test_version2: "CXNZJ.230.104")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CXNZJ.230.105");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "CXNZJ.230.200", test_version2: "CXNZJ.230.209")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CXNZJ.230.210");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:cx82[057]" || cpe =~ "^cpe:/o:lexmark:cx860" ||
    cpe =~ "^cpe:/o:lexmark:xc615[23]" || cpe =~ "^cpe:/o:lexmark:xc81(55|60|63)") {
  if (version_is_less(version: version, test_version: "CXTPP.230.042")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CXTPP.230.042");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "CXTPP.230.075", test_version2: "CXTPP.230.086")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CXTPP.230.087");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "CXTPP.230.100", test_version2: "CXTPP.230.104")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CXTPP.230.105");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "CXTPP.230.200", test_version2: "CXTPP.230.209")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CXTPP.230.210");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:cs82[07]" || cpe =~ "^cpe:/o:lexmark:c6160") {
  if (version_is_less(version: version, test_version: "CSTPP.230.042")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CSTPP.230.042");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "CSTPP.230.075", test_version2: "CSTPP.230.086")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CSTPP.230.087");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "CSTPP.230.100", test_version2: "CSTPP.230.104")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CSTPP.230.105");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "CSTPP.230.200", test_version2: "CSTPP.230.209")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CSTPP.230.210");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:cs72[0578]" || cpe =~ "^cpe:/o:lexmark:c4150") {
  if (version_is_less(version: version, test_version: "CSTAT.230.042")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CSTAT.230.042");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "CSTAT.230.075", test_version2: "CSTAT.230.086")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CSTAT.230.087");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "CSTAT.230.100", test_version2: "CSTAT.230.104")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CSTAT.230.105");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "CSTAT.230.200", test_version2: "CSTAT.230.209")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CSTAT.230.210");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:cx72[57]" || cpe =~ "^cpe:/o:lexmark:xc41(40|43|50|53)") {
  if (version_is_less(version: version, test_version: "CXTAT.230.042")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CXTAT.230.042");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "CXTAT.230.075", test_version2: "CXTAT.230.086")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CXTAT.230.087");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "CXTAT.230.100", test_version2: "CXTAT.230.104")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CXTAT.230.105");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "CXTAT.230.200", test_version2: "CXTAT.230.209")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CXTAT.230.210");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:cs92[137]" || cpe =~ "^cpe:/o:lexmark:c9235") {
  if (version_is_less(version: version, test_version: "CSTMH.230.042")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CSTMH.230.042");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "CSTMH.230.075", test_version2: "CSTMH.230.086")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CSTMH.230.087");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "CSTMH.230.100", test_version2: "CSTMH.230.104")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CSTMH.230.105");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "CSTMH.230.200", test_version2: "CSTMH.230.209")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CSTMH.230.210");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:cx92[01234]" || cpe =~ "^cpe:/o:lexmark:xc92[23456]5") {
  if (version_is_less(version: version, test_version: "CXTMH.230.042")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CXTMH.230.042");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "CXTMH.230.075", test_version2: "CXTMH.230.086")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CXTMH.230.087");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "CXTMH.230.100", test_version2: "CXTMH.230.104")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CXTMH.230.105");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "CXTMH.230.200", test_version2: "CXTMH.230.209")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CXTMH.230.210");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:ms[56]31") {
  if (version_is_less(version: version, test_version: "MSNSN.222.032")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MSNSN.222.032");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "MSNSN.230.001", test_version2: "MSNSN.230.041")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MSNSN.230.042");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "MSNSN.230.075", test_version2: "MSNSN.230.086")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MSNSN.230.087");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "MSNSN.230.100", test_version2: "MSNSN.230.104")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MSNSN.230.105");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "MSNSN.230.200", test_version2: "MSNSN.230.209")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MSNSN.230.210");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:ms632" || cpe =~ "^cpe:/o:lexmark:m3350") {
  if (version_is_less(version: version, test_version: "MSTSN.222.032")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MSTSN.222.032");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "MSTSN.230.001", test_version2: "MSTSN.230.041")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MSTSN.230.042");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "MSTSN.230.075", test_version2: "MSTSN.230.086")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MSTSN.230.087");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "MSTSN.230.100", test_version2: "MSTSN.230.104")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MSTSN.230.105");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "MSTSN.230.200", test_version2: "MSTSN.230.209")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MSTSN.230.210");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:mx[56]32" || cpe =~ "^cpe:/o:lexmark:xm3350") {
  if (version_is_less(version: version, test_version: "MXTSN.222.032")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MXTSN.222.032");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "MXTSN.230.001", test_version2: "MXTSN.230.041")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MXTSN.230.042");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "MXTSN.230.075", test_version2: "MXTSN.230.086")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MXTSN.230.087");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "MXTSN.230.100", test_version2: "MXTSN.230.104")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MXTSN.230.105");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "MXTSN.230.200", test_version2: "MXTSN.230.209")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "MXTSN.230.210");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:cs531" || cpe =~ "^cpe:/o:lexmark:c2335") {
  if (version_is_less(version: version, test_version: "CSNGV.222.032")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CSNGV.222.032");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "CSNGV.230.001", test_version2: "CSNGV.230.041")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CSNGV.230.042");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "CSNGV.230.075", test_version2: "CSNGV.230.086")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CSNGV.230.087");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "CSNGV.230.100", test_version2: "CSNGV.230.104")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CSNGV.230.105");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "CSNGV.230.200", test_version2: "CSNGV.230.209")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CSNGV.230.210");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:cs632") {
  if (version_is_less(version: version, test_version: "CSTGV.222.032")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CSTGV.222.032");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "CSTGV.230.001", test_version2: "CSTGV.230.041")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CSTGV.230.042");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "CSTGV.230.075", test_version2: "CSTGV.230.086")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CSTGV.230.087");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "CSTGV.230.100", test_version2: "CSTGV.230.104")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CSTGV.230.105");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "CSTGV.230.200", test_version2: "CSTGV.230.209")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CSTGV.230.210");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:cx532" || cpe =~ "^cpe:/o:lexmark:cx635" ||
    cpe =~ "^cpe:/o:lexmark:xc2335") {
  if (version_is_less(version: version, test_version: "CXTGV.222.032")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CXTGV.222.032");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "CXTGV.230.001", test_version2: "CXTGV.230.041")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CXTGV.230.042");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "CXTGV.230.075", test_version2: "CXTGV.230.086")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CXTGV.230.087");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "CXTGV.230.100", test_version2: "CXTGV.230.104")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CXTGV.230.105");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range(version: version, test_version: "CXTGV.230.200", test_version2: "CXTGV.230.209")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "CXTGV.230.210");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:ms[34]15" || cpe =~ "^cpe:/o:lexmark:ms417") {
  if (version_is_less(version: version, test_version: "LW90.TL2.P210")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LW90.TL2.P210");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:ms[56]1[07]" || cpe =~ "^cpe:/o:lexmark:m114[05]" ||
    cpe =~ "^cpe:/o:lexmark:m3150") {
  if (version_is_less(version: version, test_version: "LW90.PR2.P210")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LW90.PR2.P210");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:ms610de" || cpe =~ "^cpe:/o:lexmark:m3150de") {
  if (version_is_less(version: version, test_version: "LW90.PR4.P210")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LW90.PR4.P210");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:mx41[07]" || cpe =~ "^cpe:/o:lexmark:mx51[017]" ||
    cpe =~ "^cpe:/o:lexmark:xm114[05]") {
  if (version_is_less(version: version, test_version: "LW90.SB4.P210")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LW90.SB4.P210");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:mx61[017]" || cpe =~ "^cpe:/o:lexmark:xm3150") {
  if (version_is_less(version: version, test_version: "LW90.SB7.P210")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LW90.SB7.P210");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:ms71[01]" || cpe =~ "^cpe:/o:lexmark:ms81[01278]" ||
    cpe =~ "^cpe:/o:lexmark:m5163") {
  if (version_is_less(version: version, test_version: "LW90.DN2.P210")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LW90.DN2.P210");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:ms810de" || cpe =~ "^cpe:/o:lexmark:m5155" ||
    cpe =~ "^cpe:/o:lexmark:m5163de") {
  if (version_is_less_equal(version: version, test_version: "LW90.DN4.P210")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LW90.DN4.P210");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:ms812de" || cpe =~ "^cpe:/o:lexmark:m5170") {
  if (version_is_less_equal(version: version, test_version: "LW90.DN7.P210")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LW90.DN7.P210");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:mx71[0178]" || cpe =~ "^cpe:/o:lexmark:mx81[012]" ||
    cpe =~ "^cpe:/o:lexmark:xm5[12]63" || cpe =~ "^cpe:/o:lexmark:xm5[12]70" ||
    cpe =~ "^cpe:/o:lexmark:xm71(55|63|70)" || cpe =~ "^cpe:/o:lexmark:xm72(63|70)") {
  if (version_is_less_equal(version: version, test_version: "LW90.TU.P210")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LW90.TU.P210");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:ms911") {
  if (version_is_less_equal(version: version, test_version: "LW90.SA.P210")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LW90.SA.P210");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:mx91[012]" || cpe =~ "^cpe:/o:lexmark:xm91[456]5") {
  if (version_is_less_equal(version: version, test_version: "LW90.MG.P210")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LW90.MG.P210");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:mx6500e") {
  if (version_is_less_equal(version: version, test_version: "LW90.JD.P210")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LW90.JD.P210");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:cs51[07]" || cpe =~ "^cpe:/o:lexmark:c2132") {
  if (version_is_less_equal(version: version, test_version: "LW90.VY4.P210")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LW90.VY4.P210");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:cx41[07]" || cpe =~ "^cpe:/o:lexmark:xc2130") {
  if (version_is_less_equal(version: version, test_version: "LW90.GM4.P210")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LW90.GM4.P210");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:lexmark:cx51[07]" || cpe =~ "^cpe:/o:lexmark:xc2132") {
  if (version_is_less_equal(version: version, test_version: "LW90.GM7.P210")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LW90.GM7.P210");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
