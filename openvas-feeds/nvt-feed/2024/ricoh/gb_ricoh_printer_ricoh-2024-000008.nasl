# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170792");
  script_version("2024-07-26T05:05:35+0000");
  script_tag(name:"last_modification", value:"2024-07-26 05:05:35 +0000 (Fri, 26 Jul 2024)");
  script_tag(name:"creation_date", value:"2024-07-24 12:07:49 +0000 (Wed, 24 Jul 2024)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:C");

  script_cve_id("CVE-2024-39927");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("RICOH Printers Buffer Overflow Vulnerability (ricoh-2024-000008)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("gb_ricoh_printer_consolidation.nasl");
  script_mandatory_keys("ricoh/printer/detected");

  script_tag(name:"summary", value:"Multiple RICOH printers and multifunction printers are prone to
  a buffer overflow vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Please see the referenced vendor advisory for a full list of
  affected devices and firmware versions.");

  script_tag(name:"solution", value:"Please see the referenced vendor advisory for updated firmware
  versions.");

  script_xref(name:"URL", value:"https://jvn.jp/en/jp/JVN14294633/");
  script_xref(name:"URL", value:"https://www.ricoh.com/products/security/vulnerabilities/vul?id=ricoh-2024-000008");
  script_xref(name:"URL", value:"https://support.ricoh.com/bb/html/dr_ut_e/rc3/history/bb/pub_e/dr_ut_e/0001339/0001339241/V200/r02160en/history.htm");
  script_xref(name:"URL", value:"https://support.ricoh.com/bb/html/dr_ut_e/rc3/history/bb/pub_e/dr_ut_e/0001339/0001339998/V200/r02340en/history.htm");
  script_xref(name:"URL", value:"https://support.ricoh.com/bb/html/dr_ut_e/rc3/history/bb/pub_e/dr_ut_e/0001335/0001335844/V200/r02171en/history.htm");
  script_xref(name:"URL", value:"https://support.ricoh.com/bb/html/dr_ut_e/rc3/history/bb/pub_e/dr_ut_e/0001335/0001335844/V200/r02171en/history.htm");
  script_xref(name:"URL", value:"https://support.ricoh.com/bb/html/dr_ut_e/rc3/history/bb/pub_e/dr_ut_e/0001335/0001335845/V200/r02169en/history.htm");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/o:ricoh:ip_c8500_firmware",
                     "cpe:/o:ricoh:im_370_firmware",
                     "cpe:/o:ricoh:im_370f_firmware",
                     "cpe:/o:ricoh:im_460f_firmware",
                     "cpe:/o:ricoh:im_460ftl_firmware",
                     "cpe:/o:ricoh:im_c7010_firmware",
                     "cpe:/o:ricoh:im_c2010_firmware",
                     "cpe:/o:ricoh:im_c2510_firmware",
                     "cpe:/o:ricoh:im_c4510_firmware",
                     "cpe:/o:ricoh:im_c5510_firmware",
                     "cpe:/o:ricoh:im_c6010_firmware",
                     "cpe:/o:ricoh:im_c3010_firmware",
                     "cpe:/o:ricoh:im_c3510_firmware");

if (!infos = get_app_version_from_list(cpe_list: cpe_list, nofork: TRUE))
  exit(0);

version = infos["version"];
cpe = infos["cpe"];

if (cpe == "cpe:/o:ricoh:ip_c8500_firmware") {
  if (version_is_less(version: version, test_version: "1.04")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
    security_message(port: 0, data: report);
    exit(0);
  }
}

# https://support.ricoh.com/bb/html/dr_ut_e/rc3/history/bb/pub_e/dr_ut_e/0001339/0001339241/V200/r02160en/history.htm
else if (cpe == "cpe:/o:ricoh:im_370_firmware" ||
         cpe =~ "^cpe:/o:ricoh:im_(370|460)f_firmware" ||
         cpe == "cpe:/o:ricoh:im_460ftl_firmware") {
  if (version_is_less(version: version, test_version: "1.10")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "1.10");
    security_message(port: 0, data: report);
    exit(0);
  }
}

# https://support.ricoh.com/bb/html/dr_ut_e/rc3/history/bb/pub_e/dr_ut_e/0001339/0001339998/V200/r02340en/history.htm
else if (cpe == "cpe:/o:ricoh:im_c7010_firmware") {
  if (version_is_less(version: version, test_version: "1.05")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "1.05");
    security_message(port: 0, data: report);
    exit(0);
  }
}

# https://support.ricoh.com/bb/html/dr_ut_e/rc3/history/bb/pub_e/dr_ut_e/0001335/0001335844/V200/r02171en/history.htm
# https://support.ricoh.com/bb/html/dr_ut_e/rc3/history/bb/pub_e/dr_ut_e/0001335/0001335844/V200/r02171en/history.htm
else if (cpe =~ "^cpe:/o:ricoh:im_c[23][05]10_firmware") {
  if (version_is_less(version: version, test_version: "2.00")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2.00");
    security_message(port: 0, data: report);
    exit(0);
  }
}

# https://support.ricoh.com/bb/html/dr_ut_e/rc3/history/bb/pub_e/dr_ut_e/0001335/0001335845/V200/r02169en/history.htm
else if (cpe =~ "^cpe:/o:ricoh:im_c(45|55|60)10_firmware") {
  if (version_is_less(version: version, test_version: "2.00")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2.00");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
