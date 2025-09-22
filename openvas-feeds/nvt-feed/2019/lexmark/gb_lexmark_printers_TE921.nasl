# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142865");
  script_version("2024-06-28T05:05:33+0000");
  script_tag(name:"last_modification", value:"2024-06-28 05:05:33 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"creation_date", value:"2019-09-09 07:03:43 +0000 (Mon, 09 Sep 2019)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-08-29 17:14:00 +0000 (Thu, 29 Aug 2019)");

  script_cve_id("CVE-2019-10057");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Lexmark Printer CSRF Vulnerability (TE921)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("General");
  script_dependencies("gb_lexmark_printer_consolidation.nasl");
  script_mandatory_keys("lexmark_printer/detected", "lexmark_printer/model");

  script_tag(name:"summary", value:"Some Lexmark devices embedded web server contain a cross-site
  request forgery (CSRF) attack vulnerability that allows a local account password to be changed
  without the knowledge of the authenticated user.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable firmware version is present on the target host.");

  script_tag(name:"insight", value:"A vulnerability has been identified in the embedded web server used in older
  generation Lexmark devices.  The vulnerability allows an attacker to fool an authenticated user into changing
  their password.");

  script_tag(name:"impact", value:"Successful exploitation of this vulnerability can lead to the takeover of a
  local account on the device.");

  script_tag(name:"affected", value:"Lexmark models CS32x, CS41x, MS310, MS312, MS317, MS410, MS1140, MS315,
  MS415, MS417, MX31x, XM1135, MS51X, MS610dn, MS617, MS1145, M3150dn, MS71x, M5163dn, MS810, MS811, MS812,
  MS817 and MS818.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"http://support.lexmark.com/index?page=content&id=TE921");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!model = get_kb_item("lexmark_printer/model"))
  exit(0);

cpe = 'cpe:/o:lexmark:' + tolower(model) + "_firmware";
if (!version = get_app_version(cpe: cpe, nofork: TRUE))
  exit(0);

if (model =~ "^CS31") {
  if (version_is_less(version: version, test_version: "lw71.vyl.p229")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "lw71.vyl.p229");
    security_message(port: 0, data: report);
    exit(0);
  }
}
else if (model =~ "^CS41") {
  if (version_is_less(version: version, test_version: "lw71.vy2.p229")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "lw71.vy2.p229");
    security_message(port: 0, data: report);
    exit(0);
  }
}
else if (model =~ "^CX310") {
  if (version_is_less(version: version, test_version: "lw71.gm2.p229")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "lw71.gm2.p229");
    security_message(port: 0, data: report);
    exit(0);
  }
}
else if (model =~ "^(MS31[027]|MS410|M1140)") {
  if (version_is_less(version: version, test_version: "lw71.prl.p229")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "lw71.prl.p229");
    security_message(port: 0, data: report);
    exit(0);
  }
}
else if (model =~ "^(MS315|MS41[57])") {
  if (version_is_less(version: version, test_version: "lw71.tl2.p229")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "lw71.tl2.p229");
    security_message(port: 0, data: report);
    exit(0);
  }
}
else if (model =~ "^(MX31|XM1135)") {
  if (version_is_less(version: version, test_version: "lw71.sb2.p229")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "lw71.sb2.p229");
    security_message(port: 0, data: report);
    exit(0);
  }
}
else if (model =~ "^(MS51|MS610dn|MS617)") {
  if (version_is_less(version: version, test_version: "lw71.pr2.p229")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "lw71.pr2.p229");
    security_message(port: 0, data: report);
    exit(0);
  }
}
else if (model =~ "^(M1145|M3150dn)") {
  if (version_is_less(version: version, test_version: "lw71.pr2.p229")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "lw71.pr2.p229");
    security_message(port: 0, data: report);
    exit(0);
  }
}
else if (model =~ "^(MS71|M5163dn|MS81[01278])") {
  if (version_is_less(version: version, test_version: "lw71.dn2.p229")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "lw71.dn2.p229");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
