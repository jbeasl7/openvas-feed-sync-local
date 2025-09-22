# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/h:f5:big-ip";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140048");
  script_cve_id("CVE-2016-6304");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_version("2024-05-29T05:05:18+0000");

  script_name("F5 BIG-IP - OpenSSL vulnerability CVE-2016-6304");

  script_xref(name:"URL", value:"https://my.f5.com/manage/s/article/K54211024");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"summary", value:"Multiple memory leaks in t1_lib.c in OpenSSL before 1.0.1u, 1.0.2 before 1.0.2i, and 1.1.0 before 1.1.0a allow remote attackers to cause a denial of service (memory consumption) via large OCSP Status Request extensions.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"2024-05-29 05:05:18 +0000 (Wed, 29 May 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-16 13:18:00 +0000 (Tue, 16 Aug 2022)");
  script_tag(name:"creation_date", value:"2016-11-03 10:24:33 +0100 (Thu, 03 Nov 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("F5 Local Security Checks");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("gb_f5_big_ip_ssh_login_detect.nasl");
  script_mandatory_keys("f5/big_ip/version", "f5/big_ip/active_modules");
  exit(0);
}

include("f5.inc");
include("host_details.inc");
include("list_array_func.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, service: "ssh-login"))
  exit(0);

check_f5["LTM"] = make_array("affected",   "12.0.0-12.1.1;11.5.2-11.6.1;11.5.1_HF3-11.5.1_HF11;11.5.0_HF4-11.5.0_HF7;",
                             "unaffected", "11.5.1-11.5.1_HF2;11.5.0-11.5.0_HF3;11.4.0-11.4.1;11.2.1;10.2.1-10.2.4;");

check_f5["AAM"] = make_array("affected",   "12.0.0-12.1.1;11.5.2-11.6.1;11.5.1_HF3-11.5.1_HF11;11.5.0_HF4-11.5.0_HF7;",
                             "unaffected", "11.5.1-11.5.1_HF2;11.5.0-11.5.0_HF3;11.4.0-11.4.1;");

check_f5["AFM"] = make_array("affected",   "12.0.0-12.1.1;11.5.2-11.6.1;11.5.1_HF3-11.5.1_HF11;11.5.0_HF4-11.5.0_HF7;",
                             "unaffected", "11.5.1-11.5.1_HF2;11.5.0-11.5.0_HF3;11.4.0-11.4.1;");

check_f5["AVR"] = make_array("affected",   "12.0.0-12.1.1;11.5.2-11.6.1;11.5.1_HF3-11.5.1_HF11;11.5.0_HF4-11.5.0_HF7;",
                             "unaffected", "11.5.1-11.5.1_HF2;11.5.0-11.5.0_HF3;11.4.0-11.4.1;11.2.1;");

check_f5["APM"] = make_array("affected",   "12.0.0-12.1.1;11.5.2-11.6.1;11.5.1_HF3-11.5.1_HF11;11.5.0_HF4-11.5.0_HF7;",
                             "unaffected", "11.5.1-11.5.1_HF2;11.5.0-11.5.0_HF3;11.4.0-11.4.1;11.2.1;10.2.1-10.2.4;");

check_f5["ASM"] = make_array("affected",   "12.0.0-12.1.1;11.5.2-11.6.1;11.5.1_HF3-11.5.1_HF11;11.5.0_HF4-11.5.0_HF7;",
                             "unaffected", "11.5.1-11.5.1_HF2;11.5.0-11.5.0_HF3;11.4.0-11.4.1;11.2.1;10.2.1-10.2.4;");

check_f5["GTM"] = make_array("affected",   "11.5.2-11.6.1;11.5.1_HF3-11.5.1_HF11;11.5.0_HF4-11.5.0_HF7;",
                             "unaffected", "11.5.1-11.5.1_HF2;11.5.0-11.5.0_HF3;11.4.0-11.4.1;11.2.1;10.2.1-10.2.4;");

check_f5["LC"]  = make_array("affected",   "12.0.0-12.1.1;11.5.2-11.6.1;11.5.1_HF3-11.5.1_HF11;11.5.0_HF4-11.5.0_HF7;",
                             "unaffected", "11.5.1-11.5.1_HF2;11.5.0-11.5.0_HF3;11.4.0-11.4.1;11.2.1;10.2.1-10.2.4;");

check_f5["PEM"] = make_array("affected",   "12.0.0-12.1.1;11.5.2-11.6.1;11.5.1_HF3-11.5.1_HF11;11.5.0_HF4-11.5.0_HF7;",
                             "unaffected", "11.5.1-11.5.1_HF2;11.5.0-11.5.0_HF3;11.4.0-11.4.1;");

if (report = f5_is_vulnerable(ca: check_f5, version: version)) {
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
