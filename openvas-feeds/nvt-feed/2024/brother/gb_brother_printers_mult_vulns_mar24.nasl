# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170787");
  script_version("2024-05-17T05:05:27+0000");
  script_tag(name:"last_modification", value:"2024-05-17 05:05:27 +0000 (Fri, 17 May 2024)");
  script_tag(name:"creation_date", value:"2024-05-14 19:35:38 +0000 (Tue, 14 May 2024)");
  script_tag(name:"cvss_base", value:"2.9");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2024-21824", "CVE-2024-22475");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Brother Printers Multiple Vulnerabilities (Mar 2024)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("gb_brother_printer_consolidation.nasl");
  script_mandatory_keys("brother/printer/detected");

  script_tag(name:"summary", value:"Multiple Brother printers are prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable firmware version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2024-21824: Attackers can gain access to the server's setting screen by obtaining session IDs of
  logged-in users and impersonating them, or by stealing login credentials and tricking users into opening
  malicious URLs.

  - CVE-2024-22475: Cross-site request forgery vulnerability allows a remote unauthenticated attacker to
  perform unintended operations on the affected product.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://jvn.jp/en/jp/JVN82749078/");
  script_xref(name:"URL", value:"https://support.brother.com/g/b/faqend.aspx?c=us&lang=en&prod=group2&faqid=faq00100823_000");
  script_xref(name:"URL", value:"https://support.brother.com/g/s/id/security/CVE-2024-21824_22475_modellist.pdf");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/o:brother:dcp-1610w_firmware",
                     "cpe:/o:brother:dcp-1610we_firmware",
                     "cpe:/o:brother:dcp-1610wr_firmware",
                     "cpe:/o:brother:dcp-1610wvb_firmware",
                     "cpe:/o:brother:dcp-1612w_firmware",
                     "cpe:/o:brother:dcp-1612we_firmware",
                     "cpe:/o:brother:dcp-1612wr_firmware",
                     "cpe:/o:brother:dcp-1612wvb_firmware",
                     "cpe:/o:brother:dcp-1615nw_firmware",
                     "cpe:/o:brother:dcp-1616nw_firmware",
                     "cpe:/o:brother:dcp-1617nw_firmware",
                     "cpe:/o:brother:dcp-1618w_firmware",
                     "cpe:/o:brother:dcp-1622we_firmware",
                     "cpe:/o:brother:dcp-1623we_firmware",
                     "cpe:/o:brother:dcp-1623wr_firmware",
                     "cpe:/o:brother:dcp-7180dn_firmware",
                     "cpe:/o:brother:dcp-l2520dw_firmware",
                     "cpe:/o:brother:dcp-l2520dwr_firmware",
                     "cpe:/o:brother:dcp-l2540dn_firmware",
                     "cpe:/o:brother:dcp-l2540dnr_firmware",
                     "cpe:/o:brother:dcp-l2540dw_firmware",
                     "cpe:/o:brother:dcp-l2541dw_firmware",
                     "cpe:/o:brother:dcp-l2560dw_firmware",
                     "cpe:/o:brother:dcp-l2560dwr_firmware",
                     "cpe:/o:brother:fax-l2700dn_firmware",
                     "cpe:/o:brother:hl-1210w_firmware",
                     "cpe:/o:brother:hl-1210we_firmware",
                     "cpe:/o:brother:hl-1210wr_firmware",
                     "cpe:/o:brother:hl-1210wvb_firmware",
                     "cpe:/o:brother:hl-1211w_firmware",
                     "cpe:/o:brother:hl-1212w_firmware",
                     "cpe:/o:brother:hl-1212we_firmware",
                     "cpe:/o:brother:hl-1212wr_firmware",
                     "cpe:/o:brother:hl-1212wvb_firmware",
                     "cpe:/o:brother:hl-1218w_firmware",
                     "cpe:/o:brother:hl-1222we_firmware",
                     "cpe:/o:brother:hl-1223we_firmware",
                     "cpe:/o:brother:hl-1223wr_firmware",
                     "cpe:/o:brother:hl-2560dn_firmware",
                     "cpe:/o:brother:hl-l2305w_firmware",
                     "cpe:/o:brother:hl-l2315dw_firmware",
                     "cpe:/o:brother:hl-l2340dw_firmware",
                     "cpe:/o:brother:hl-l2340dwr_firmware",
                     "cpe:/o:brother:hl-l2360dn_firmware",
                     "cpe:/o:brother:hl-l2360dnr_firmware",
                     "cpe:/o:brother:hl-l2360dw_firmware",
                     "cpe:/o:brother:hl-l2361dn_firmware",
                     "cpe:/o:brother:hl-l2365dw_firmware",
                     "cpe:/o:brother:hl-l2365dwr_firmware",
                     "cpe:/o:brother:hl-l2366dw_firmware",
                     "cpe:/o:brother:hl-l2380dw_firmware",
                     "cpe:/o:brother:mfc-1910w_firmware",
                     "cpe:/o:brother:mfc-1910we_firmware",
                     "cpe:/o:brother:mfc-1911nw_firmware",
                     "cpe:/o:brother:mfc-1911w_firmware",
                     "cpe:/o:brother:mfc-1912wr_firmware",
                     "cpe:/o:brother:mfc-1915w_firmware",
                     "cpe:/o:brother:mfc-1916nw_firmware",
                     "cpe:/o:brother:mfc-1919nw_firmware",
                     "cpe:/o:brother:mfc-7880dn_firmware",
                     "cpe:/o:brother:mfc-l2680w_firmware",
                     "cpe:/o:brother:mfc-l2685dw_firmware",
                     "cpe:/o:brother:mfc-l2700dn_firmware",
                     "cpe:/o:brother:mfc-l2700dnr_firmware",
                     "cpe:/o:brother:mfc-l2700dw_firmware",
                     "cpe:/o:brother:mfc-l2700dwr_firmware",
                     "cpe:/o:brother:mfc-l2701dw_firmware",
                     "cpe:/o:brother:mfc-l2703dw_firmware",
                     "cpe:/o:brother:mfc-l2705dw_firmware",
                     "cpe:/o:brother:mfc-l2707dw_firmware",
                     "cpe:/o:brother:mfc-l2720dn_firmware",
                     "cpe:/o:brother:mfc-l2720dw_firmware",
                     "cpe:/o:brother:mfc-l2720dwr_firmware",
                     "cpe:/o:brother:mfc-l2740dw_firmware",
                     "cpe:/o:brother:mfc-l2740dwr_firmware",
                     "cpe:/o:brother:mfc-l8610cdw_firmware",
                     "cpe:/o:brother:dcp-j4120dw_firmware",
                     "cpe:/o:brother:dcp-j4220n-b_firmware",
                     "cpe:/o:brother:dcp-j4220n-w_firmware",
                     "cpe:/o:brother:dcp-j4225n-b_firmware",
                     "cpe:/o:brother:dcp-j4225n-w_firmware",
                     "cpe:/o:brother:mfc-j2320_firmware",
                     "cpe:/o:brother:mfc-j2720_firmware",
                     "cpe:/o:brother:mfc-j3520_firmware",
                     "cpe:/o:brother:mfc-j3720_firmware",
                     "cpe:/o:brother:mfc-j4320dw_firmware",
                     "cpe:/o:brother:mfc-j4420dw_firmware",
                     "cpe:/o:brother:mfc-j4520dw_firmware",
                     "cpe:/o:brother:mfc-j4620dw_firmware",
                     "cpe:/o:brother:mfc-j4625dw_firmware",
                     "cpe:/o:brother:mfc-j4720n_firmware",
                     "cpe:/o:brother:mfc-j4725n_firmware",
                     "cpe:/o:brother:mfc-j5320dw_firmware",
                     "cpe:/o:brother:mfc-j5520dw_firmware",
                     "cpe:/o:brother:mfc-j5620cdw_firmware",
                     "cpe:/o:brother:mfc-j5620dw_firmware",
                     "cpe:/o:brother:mfc-j5625dw_firmware",
                     "cpe:/o:brother:mfc-j5720dw_firmware",
                     "cpe:/o:brother:mfc-j5820dn_firmware",
                     "cpe:/o:brother:mfc-j5920dw_firmware",
                     "cpe:/o:brother:mfc-j6520dw_firmware",
                     "cpe:/o:brother:mfc-j6570cdw_firmware",
                     "cpe:/o:brother:mfc-j6720dw_firmware",
                     "cpe:/o:brother:mfc-j6770cdw_firmware",
                     "cpe:/o:brother:mfc-j6973cdw_firmware",
                     "cpe:/o:brother:mfc-j6990cdw_firmware");

if (!infos = get_app_version_from_list(cpe_list: cpe_list, nofork: TRUE))
  exit(0);

version = infos["version"];
cpe = infos["cpe"];


if (cpe =~ "^cpe:/o:brother:dcp-161[02](w|we|wr|wvb)_firmware" ||
    cpe == "cpe:/o:brother:dcp-1622we_firmware" ||
    cpe =~ "^cpe:/o:brother:dcp-1623w[er]_firmware") {
  if (version_is_less(version: version, test_version: "ZA")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "ZA");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:brother:dcp-161[567]nw_firmware") {
  if (version_is_less(version: version, test_version: "S")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "S");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:brother:dcp-1618w_firmware" ||
    cpe == "cpe:/o:brother:dcp-7180dn_firmware") {
  if (version_is_less(version: version, test_version: "R")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "R");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:brother:dcp-l2520(dw|dwr)_firmware") {
  if (version_is_less(version: version, test_version: "X")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "X");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:brother:dcp-l2540(dn|dnr|dw)_firmware" ||
    cpe == "cpe:/o:brother:dcp-l2541dw_firmware") {
  if (version_is_less(version: version, test_version: "Y")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "Y");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:brother:dcp-l2560(dw|dwr)_firmware") {
  if (version_is_less(version: version, test_version: "W")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "W");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:brother:fax-l2700dn_firmware") {
  if (version_is_less(version: version, test_version: "R")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "R");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:brother:hl-121[02](w|we|wr|wvb)_firmware" ||
    cpe =~ "^cpe:/o:brother:hl-121[18]w_firmware" ||
    cpe =~ "^cpe:/o:brother:hl-122[23]we_firmware" ||
    cpe == "cpe:/o:brother:hl-1223wr_firmware") {
  if (version_is_less(version: version, test_version: "1.21")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "1.21");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:brother:hl-2560dn_firmware") {
  if (version_is_less(version: version, test_version: "1.36")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "1.36");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:brother:hl-l2305w_firmware" ||
    cpe == "cpe:/o:brother:hl-l2315dw_firmware") {
  if (version_is_less(version: version, test_version: "1.25")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "1.25");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:brother:hl-l2340(dw|dwr)_firmware") {
  if (version_is_less(version: version, test_version: "1.27")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "1.27");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:brother:hl-l2360(dn|dnr|dw)_firmware" ||
    cpe == "cpe:/o:brother:hl-l2361dn_firmware" ||
    cpe =~ "^cpe:/o:brother:hl-l236[56]dw_firmware" ||
    cpe == "cpe:/o:brother:hl-l2365dwr_firmware") {
  if (version_is_less(version: version, test_version: "1.36")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "1.36");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:brother:hl-l2380dw_firmware") {
  if (version_is_less(version: version, test_version: "V")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "W");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:brother:mfc-1910(w|we)_firmware" ||
    cpe =~ "^cpe:/o:brother:mfc-1911(nw|w)_firmware" ||
    cpe == "cpe:/o:brother:mfc-1912wr_firmware" ||
    cpe == "cpe:/o:brother:mfc-1915w_firmware" ||
    cpe == "cpe:/o:brother:mfc-1916nw_firmware") {
  if (version_is_less(version: version, test_version: "U")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "U");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:brother:mfc-1919nw_firmware") {
  if (version_is_less(version: version, test_version: "R")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "R");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:brother:mfc-7880dn_firmware") {
  if (version_is_less(version: version, test_version: "S")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "S");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:brother:mfc-l2680w_firmware" ||
    cpe == "cpe:/o:brother:mfc-l2685dw_firmware" ||
    cpe =~ "^cpe:/o:brother:mfc-l2700(dn|dnr|dw|dwr)_firmware") {
  if (version_is_less(version: version, test_version: "Y")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "Y");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:brother:mfc-l270[1357]dw_firmware" ||
    cpe =~ "^cpe:/o:brother:mfc-l2740(dw|dwr)_firmware") {
  if (version_is_less(version: version, test_version: "W")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "W");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:brother:mfc-l2720dn_firmware") {
  if (version_is_less(version: version, test_version: "T")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "T");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:brother:mfc-l2720(dw|dwr)_firmware") {
  if (version_is_less(version: version, test_version: "X")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "X");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:brother:dcp-j4120dw_firmware" ||
    cpe =~ "^cpe:/o:brother:dcp-j4220n-[bw]_firmware") {
  if (version_is_less(version: version, test_version: "N")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "N");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:brother:dcp-j4225n-[bw]_firmware") {
  if (version_is_less(version: version, test_version: "J")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "J");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:brother:mfc-j2320_firmware") {
  if (version_is_less(version: version, test_version: "M")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "M");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:brother:mfc-j2720_firmware") {
  if (version_is_less(version: version, test_version: "R")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "R");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:brother:mfc-j4[34]20dw_firmware") {
  if (version_is_less(version: version, test_version: "T")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "T");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:brother:mfc-j4[56]20dw_firmware" ||
    cpe == "cpe:/o:brother:mfc-j4625dw_firmware") {
  if (version_is_less(version: version, test_version: "V")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "V");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:brother:mfc-j4720n_firmware") {
  if (version_is_less(version: version, test_version: "N")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "N");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:brother:mfc-j4725n_firmware") {
  if (version_is_less(version: version, test_version: "J")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "J");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:brother:mfc-j5320dw_firmware") {
  if (version_is_less(version: version, test_version: "M")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "M");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:brother:mfc-j5520dw_firmware" ||
    cpe =~ "^cpe:/o:brother:mfc-j562[05]dw_firmware") {
  if (version_is_less(version: version, test_version: "S")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "S");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:brother:mfc-j5620cdw_firmware") {
  if (version_is_less(version: version, test_version: "K")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "K");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:brother:mfc-j5[79]20dw_firmware") {
  if (version_is_less(version: version, test_version: "R")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "R");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:brother:mfc-j5820dn_firmware") {
  if (version_is_less(version: version, test_version: "L")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "L");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:brother:mfc-j6[57]20dw_firmware") {
  if (version_is_less(version: version, test_version: "U")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "U");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:brother:mfc-j6570dw_firmware" ||
    cpe == "cpe:/o:brother:mfc-j6770cdw_firmware") {
  if (version_is_less(version: version, test_version: "R")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "R");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:brother:mfc-j6580cdw_firmware") {
  if (version_is_less(version: version, test_version: "R")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "R");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:brother:mfc-j69(73|90)cdw_firmware") {
  if (version_is_less(version: version, test_version: "K")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "K");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);