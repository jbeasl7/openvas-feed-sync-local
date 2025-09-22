# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.171526");
  script_version("2025-05-23T15:42:02+0000");
  script_tag(name:"last_modification", value:"2025-05-23 15:42:02 +0000 (Fri, 23 May 2025)");
  script_tag(name:"creation_date", value:"2025-05-21 08:49:16 +0000 (Wed, 21 May 2025)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");

  script_cve_id("CVE-2025-41393");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("RICOH Printers XSS Vulnerability (ricoh-2025-000001)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("General");
  script_dependencies("gb_ricoh_printer_consolidation.nasl");
  script_mandatory_keys("ricoh/printer/detected");

  script_tag(name:"summary", value:"Multiple RICOH printers and multifunction printers are prone to
  a cross-site scripting (XSS) vulnerability via the Web Image Monitor.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Please see the referenced vendor advisory for a full list of
  affected devices and Web Image Monitor versions.");

  script_tag(name:"solution", value:"Please see the referenced vendor advisory for updated firmware
  versions.");

  script_xref(name:"URL", value:"https://jvn.jp/en/jp/JVN20474768/");
  script_xref(name:"URL", value:"https://www.ricoh.com/products/security/vulnerabilities/vul?id=ricoh-2025-000001");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/o:ricoh:mp_c3004_firmware",
                     "cpe:/o:ricoh:mp_c3004ex_firmware",
                     "cpe:/o:ricoh:mp_c3504_firmware",
                     "cpe:/o:ricoh:mp_c3504ex_firmware",
                     "cpe:/o:ricoh:mp_c2004_firmware",
                     "cpe:/o:ricoh:mp_c2004ex_firmware",
                     "cpe:/o:ricoh:mp_c2504_firmware",
                     "cpe:/o:ricoh:mp_c2504ex_firmware",
                     "cpe:/o:ricoh:mp_c4504_firmware",
                     "cpe:/o:ricoh:mp_c4504ex_firmware",
                     "cpe:/o:ricoh:mp_c5504_firmware",
                     "cpe:/o:ricoh:mp_c5504ex_firmware",
                     "cpe:/o:ricoh:mp_c6004_firmware",
                     "cpe:/o:ricoh:mp_c6004ex_firmware",
                     "cpe:/o:ricoh:im_350f_firmware",
                     "cpe:/o:ricoh:im_350_firmware",
                     "cpe:/o:ricoh:im_430f_firmware",
                     "cpe:/o:ricoh:im_430fb_firmware",
                     "cpe:/o:ricoh:m_c320fw_firmware",
                     "cpe:/o:ricoh:m_c320fse_firmware",
                     "cpe:/o:ricoh:p_c375_firmware",
                     "cpe:/o:ricoh:im_550f_firmware",
                     "cpe:/o:ricoh:im_600f_firmware",
                     "cpe:/o:ricoh:im_600srf_firmware",
                     "cpe:/o:ricoh:sp_5300dn_firmware",
                     "cpe:/o:ricoh:sp_5310dn_firmware",
                     "cpe:/o:ricoh:p_800_firmware",
                     "cpe:/o:ricoh:p_801_firmware",
                     "cpe:/o:ricoh:p_501_firmware",
                     "cpe:/o:ricoh:p_502_firmware",
                     "cpe:/o:ricoh:im_2500_firmware",
                     "cpe:/o:ricoh:im_3000_firmware",
                     "cpe:/o:ricoh:im_3500_firmware",
                     "cpe:/o:ricoh:im_4000_firmware",
                     "cpe:/o:ricoh:im_5000_firmware",
                     "cpe:/o:ricoh:im_6000_firmware",
                     "cpe:/o:ricoh:sp_8400dn_firmware",
                     "cpe:/o:ricoh:mp_402spf_firmware",
                     "cpe:/o:ricoh:im_c400f_firmware",
                     "cpe:/o:ricoh:im_c400srf_firmware",
                     "cpe:/o:ricoh:im_c300f_firmware",
                     "cpe:/o:ricoh:im_c300_firmware",
                     "cpe:/o:ricoh:p_c600_firmware",
                     "cpe:/o:ricoh:im_370_firmware",
                     "cpe:/o:ricoh:im_370f_firmware",
                     "cpe:/o:ricoh:im_460_firmware",
                     "cpe:/o:ricoh:im_460ftl_firmware",
                     "cpe:/o:ricoh:im_7000_firmware",
                     "cpe:/o:ricoh:im_8000_firmware",
                     "cpe:/o:ricoh:im_9000_firmware",
                     "cpe:/o:ricoh:im_c3000_firmware",
                     "cpe:/o:ricoh:im_c3500_firmware",
                     "cpe:/o:ricoh:im_c4500_firmware",
                     "cpe:/o:ricoh:im_c5500_firmware",
                     "cpe:/o:ricoh:im_c6000_firmware",
                     "cpe:/o:ricoh:m_c2001_firmware",
                     "cpe:/o:ricoh:im_c2000_firmware",
                     "cpe:/o:ricoh:im_c2500_firmware",
                     "cpe:/o:ricoh:im_c3010_firmware",
                     "cpe:/o:ricoh:im_c3510_firmware",
                     "cpe:/o:ricoh:im_c4510_firmware",
                     "cpe:/o:ricoh:im_c5510_firmware",
                     "cpe:/o:ricoh:im_c6010_firmware",
                     "cpe:/o:ricoh:im_c2010_firmware",
                     "cpe:/o:ricoh:im_c2510_firmware",
                     "cpe:/o:ricoh:im_c7010_firmware",
                     "cpe:/o:ricoh:sp_c352dn_firmware",
                     "cpe:/o:ricoh:im_cw2200_firmware",
                     "cpe:/o:ricoh:ip_cw2200_firmware");

if (!infos = get_app_version_from_list(cpe_list: cpe_list, nofork: TRUE))
  exit(0);

cpe = infos["cpe"];

if (!web_version = get_kb_item("ricoh/printer/web_version"))
  exit(0);

# https://www.ricoh.com/products/security/vulnerabilities/adv?id=ricoh-prod000002-2025-000001
# https://www.ricoh.com/products/security/vulnerabilities/adv?id=ricoh-prod000004-2025-000001
if (cpe =~ "^cpe:/o:ricoh:mp_c[23][05]04_firmware") {
  if (version_is_less(version: web_version, test_version: "1.25")) {
    report = report_fixed_ver(installed_version: web_version, fixed_version: "See advisory");
    security_message(port: 0, data: report);
    exit(0);
  }
}

# https://www.ricoh.com/products/security/vulnerabilities/adv?id=ricoh-prod000003-2025-000001
else if (cpe =~ "^cpe:/o:ricoh:mp_c(45|55|60)04_firmware") {
  if (version_is_less(version: web_version, test_version: "1.26")) {
    report = report_fixed_ver(installed_version: web_version, fixed_version: "See advisory");
    security_message(port: 0, data: report);
    exit(0);
  }
}

# https://www.ricoh.com/products/security/vulnerabilities/adv?id=ricoh-prod000035-2025-000001
# https://www.ricoh.com/products/security/vulnerabilities/adv?id=ricoh-prod000036-2025-000001
# https://www.ricoh.com/products/security/vulnerabilities/adv?id=ricoh-prod000037-2025-000001
if (cpe =~ "^cpe:/o:ricoh:mp_c[23][05]04ex_firmware" ||
    cpe =~ "^cpe:/o:ricoh:mp_c(45|55|60)04ex_firmware") {
  if (version_is_less(version: web_version, test_version: "1.18")) {
    report = report_fixed_ver(installed_version: web_version, fixed_version: "See advisory");
    security_message(port: 0, data: report);
    exit(0);
  }
}

# https://www.ricoh.com/products/security/vulnerabilities/adv?id=ricoh-prod000016-2025-000001
if (cpe =~ "^cpe:/o:ricoh:im_350(|f)_firmware" ||
    cpe =~ "^cpe:/o:ricoh:im_430f(|b)_firmware") {
  if (version_is_less_equal(version: web_version, test_version: "1.14")) {
    report = report_fixed_ver(installed_version: web_version, fixed_version: "See advisory");
    security_message(port: 0, data: report);
    exit(0);
  }
}

# https://www.ricoh.com/products/security/vulnerabilities/adv?id=ricoh-prod000268-2025-000001
if (cpe =~ "^cpe:/o:ricoh:m_c320f(w|se)_firmware") {
  if (version_is_less_equal(version: web_version, test_version: "1.09")) {
    report = report_fixed_ver(installed_version: web_version, fixed_version: "See advisory");
    security_message(port: 0, data: report);
    exit(0);
  }
}

# https://www.ricoh.com/products/security/vulnerabilities/adv?id=ricoh-prod000269-2025-000001
if (cpe == "cpe:/o:ricoh:p_c375_firmware") {
  if (version_is_less_equal(version: web_version, test_version: "1.07.1")) {
    report = report_fixed_ver(installed_version: web_version, fixed_version: "See advisory");
    security_message(port: 0, data: report);
    exit(0);
  }
}

# https://www.ricoh.com/products/security/vulnerabilities/adv?id=ricoh-prod000013-2025-000001
if (cpe =~ "^cpe:/o:ricoh:im_(55|60)0f_firmware" ||
    cpe == "cpe:/o:ricoh:im_600srf_firmware") {
  if (version_is_less_equal(version: web_version, test_version: "7.04")) {
    report = report_fixed_ver(installed_version: web_version, fixed_version: "See advisory");
    security_message(port: 0, data: report);
    exit(0);
  }
}

# https://www.ricoh.com/products/security/vulnerabilities/adv?id=ricoh-prod000135-2025-000001
# https://www.ricoh.com/products/security/vulnerabilities/adv?id=ricoh-prod000136-2025-000001
if (cpe =~ "^cpe:/o:ricoh:sp_53[01]0dn_firmware" ||
    cpe =~ "^cpe:/o:ricoh:p_80[01]_firmware") {
  if (version_is_less_equal(version: web_version, test_version: "1.08")) {
    report = report_fixed_ver(installed_version: web_version, fixed_version: "See advisory");
    security_message(port: 0, data: report);
    exit(0);
  }
}

# https://www.ricoh.com/products/security/vulnerabilities/adv?id=ricoh-prod000137-2025-000001
if (cpe =~ "^cpe:/o:ricoh:p_50[12]_firmware") {
  if (version_is_less_equal(version: web_version, test_version: "1.11")) {
    report = report_fixed_ver(installed_version: web_version, fixed_version: "See advisory");
    security_message(port: 0, data: report);
    exit(0);
  }
}

# https://www.ricoh.com/products/security/vulnerabilities/adv?id=ricoh-prod000010-2025-000001
if (cpe =~ "^cpe:/o:ricoh:im_[23]500_firmware" ||
    cpe =~ "^cpe:/o:ricoh:im_[3456]000_firmware") {
  if (version_is_less_equal(version: web_version, test_version: "6.04")) {
    report = report_fixed_ver(installed_version: web_version, fixed_version: "See advisory");
    security_message(port: 0, data: report);
    exit(0);
  }
}

# https://www.ricoh.com/products/security/vulnerabilities/adv?id=ricoh-prod000138-2025-000001
if (cpe == "cpe:/o:ricoh:sp_8400dn_firmware") {
  if (version_is_less_equal(version: web_version, test_version: "1.16")) {
    report = report_fixed_ver(installed_version: web_version, fixed_version: "See advisory");
    security_message(port: 0, data: report);
    exit(0);
  }
}
# https://www.ricoh.com/products/security/vulnerabilities/adv?id=ricoh-prod000057-2025-000001
if (cpe == "cpe:/o:ricoh:mp_402spf_firmware") {
  if (version_is_less_equal(version: web_version, test_version: "1.14")) {
    report = report_fixed_ver(installed_version: web_version, fixed_version: "See advisory");
    security_message(port: 0, data: report);
    exit(0);
  }
}

# https://www.ricoh.com/products/security/vulnerabilities/adv?id=ricoh-prod000008-2025-000001
if (cpe =~ "^cpe:/o:ricoh:im_c400(f|srf)_firmware" ||
    cpe =~ "^cpe:/o:ricoh:im_c300(|f)_firmware") {
  if (version_is_less_equal(version: web_version, test_version: "7.03")) {
    report = report_fixed_ver(installed_version: web_version, fixed_version: "See advisory");
    security_message(port: 0, data: report);
    exit(0);
  }
}

# https://www.ricoh.com/products/security/vulnerabilities/adv?id=ricoh-prod000143-2025-000001
if (cpe == "cpe:/o:ricoh:p_c600_firmware") {
  if (version_is_less_equal(version: web_version, test_version: "1.07")) {
    report = report_fixed_ver(installed_version: web_version, fixed_version: "See advisory");
    security_message(port: 0, data: report);
    exit(0);
  }
}

# https://www.ricoh.com/products/security/vulnerabilities/adv?id=ricoh-prod000160-2025-000001
if (cpe =~ "^cpe:/o:ricoh:im_370(|f)_firmware" ||
    cpe =~ "^cpe:/o:ricoh:im_460f(|tl)_firmware") {
  if (version_is_less_equal(version: web_version, test_version: "2.03")) {
    report = report_fixed_ver(installed_version: web_version, fixed_version: "See advisory");
    security_message(port: 0, data: report);
    exit(0);
  }
}

# https://www.ricoh.com/products/security/vulnerabilities/adv?id=ricoh-prod000012-2025-000001
if (cpe =~ "^cpe:/o:ricoh:im_[789]000_firmware") {
  if (version_is_less_equal(version: web_version, test_version: "4.05")) {
    report = report_fixed_ver(installed_version: web_version, fixed_version: "See advisory");
    security_message(port: 0, data: report);
    exit(0);
  }
}

# https://www.ricoh.com/products/security/vulnerabilities/adv?id=ricoh-prod000005-2025-000001
# https://www.ricoh.com/products/security/vulnerabilities/adv?id=ricoh-prod000006-2025-000001
# https://www.ricoh.com/products/security/vulnerabilities/adv?id=ricoh-prod000007-2025-000001
if (cpe =~ "^cpe:/o:ricoh:im_c[236]000_firmware" ||
    cpe =~ "^cpe:/o:ricoh:im_c[2345]500_firmware") {
  if (version_is_less_equal(version: web_version, test_version: "9.02")) {
    report = report_fixed_ver(installed_version: web_version, fixed_version: "See advisory");
    security_message(port: 0, data: report);
    exit(0);
  }
}
# https://www.ricoh.com/products/security/vulnerabilities/adv?id=ricoh-prod000018-2025-000001
if (cpe == "cpe:/o:ricoh:m_c2001_firmware") {
  if (version_is_less_equal(version: web_version, test_version: "2.02")) {
    report = report_fixed_ver(installed_version: web_version, fixed_version: "See advisory");
    security_message(port: 0, data: report);
    exit(0);
  }
}

# https://www.ricoh.com/products/security/vulnerabilities/adv?id=ricoh-prod000156-2025-000001
# https://www.ricoh.com/products/security/vulnerabilities/adv?id=ricoh-prod000157-2025-000001
# https://www.ricoh.com/products/security/vulnerabilities/adv?id=ricoh-prod000158-2025-000001
if (cpe =~ "^cpe:/o:ricoh:im_c[236]010_firmware" ||
    cpe =~ "^cpe:/o:ricoh:im_c[2345]510_firmware") {
  if (version_is_less_equal(version: web_version, test_version: "2.04")) {
    report = report_fixed_ver(installed_version: web_version, fixed_version: "See advisory");
    security_message(port: 0, data: report);
    exit(0);
  }
}
# https://www.ricoh.com/products/security/vulnerabilities/adv?id=ricoh-prod000159-2025-000001
if (cpe == "cpe:/o:ricoh:m_c7010_firmware") {
  if (version_is_less_equal(version: web_version, test_version: "2.05")) {
    report = report_fixed_ver(installed_version: web_version, fixed_version: "See advisory");
    security_message(port: 0, data: report);
    exit(0);
  }
}
# https://www.ricoh.com/products/security/vulnerabilities/adv?id=ricoh-prod000060-2025-000001
if (cpe == "cpe:/o:ricoh:im_cw2200_firmware") {
  if (version_is_less_equal(version: web_version, test_version: "1.06")) {
    report = report_fixed_ver(installed_version: web_version, fixed_version: "See advisory");
    security_message(port: 0, data: report);
    exit(0);
  }
}

# https://www.ricoh.com/products/security/vulnerabilities/adv?id=ricoh-prod000162-2025-000001
if (cpe == "cpe:/o:ricoh:ip_cw2200_firmware") {
  if (version_is_less_equal(version: web_version, test_version: "1.03")) {
    report = report_fixed_ver(installed_version: web_version, fixed_version: "See advisory");
    security_message(port: 0, data: report);
    exit(0);
  }
}
# https://www.ricoh.com/products/security/vulnerabilities/adv?id=ricoh-prod000239-2025-000001
if (cpe == "cpe:/o:ricoh:sp_c352dn_firmware") {
  if (version_is_less_equal(version: web_version, test_version: "1.08")) {
    report = report_fixed_ver(installed_version: web_version, fixed_version: "See advisory");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
