# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/h:f5:big-ip";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105396");
  script_cve_id("CVE-2015-0209");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_version("2024-05-29T05:05:18+0000");

  script_name("F5 BIG-IP - OpenSSL vulnerability CVE-2015-0209");

  script_xref(name:"URL", value:"https://my.f5.com/manage/s/article/K16323");

  script_tag(name:"impact", value:"An attacker may be able to cause a denial-of-service (DoS) using a malformed Elliptic Curve (EC) private-key file.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Use-after-free vulnerability in the d2i_ECPrivateKey function in crypto/ec/ec_asn1.c in OpenSSL before 0.9.8zf, 1.0.0 before 1.0.0r, 1.0.1 before 1.0.1m, and 1.0.2 before 1.0.2a might allow remote attackers to cause a denial of service (memory corruption and application crash) or possibly have unspecified other impacts via a malformed Elliptic Curve (EC) private-key file that is improperly handled during import. (CVE-2015-0209)");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"summary", value:"The remote host is missing a security patch.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"2024-05-29 05:05:18 +0000 (Wed, 29 May 2024)");
  script_tag(name:"creation_date", value:"2015-10-07 12:11:46 +0200 (Wed, 07 Oct 2015)");
  script_category(ACT_GATHER_INFO);
  script_family("F5 Local Security Checks");
  script_copyright("Copyright (C) 2015 Greenbone AG");
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

check_f5["LTM"] = make_array("affected",   "11.0.0-11.6.0;10.0.1-10.2.4;",
                             "unaffected", "12.1.0;12.0.0;11.6.1;11.6.0_HF5;11.5.4;11.5.3_HF2;11.4.1_HF9;11.2.1_HF15;");

check_f5["AAM"] = make_array("affected",   "11.4.0-11.6.0;",
                             "unaffected", "12.1.0;12.0.0;11.6.1;11.6.0_HF5;11.5.4;11.5.3_HF2;11.4.1_HF9;");

check_f5["AFM"] = make_array("affected",   "11.3.0-11.6.0;",
                             "unaffected", "12.1.0;12.0.0;11.6.1;11.5.4;");

check_f5["AVR"] = make_array("affected",   "11.0.0-11.6.0;",
                             "unaffected", "12.1.0;12.0.0;11.6.1;11.6.0_HF5;11.5.4;11.5.3_HF2;11.4.1_HF9;11.2.1_HF15;");

check_f5["APM"] = make_array("affected",   "11.0.0-11.6.0;10.1.0-10.2.4;",
                             "unaffected", "12.1.0;12.0.0;11.6.1;11.6.0_HF5;11.5.4;11.5.3_HF2;11.4.1_HF9;11.2.1_HF15;");

check_f5["ASM"] = make_array("affected",   "11.0.0-11.6.0;10.1.0-10.2.4;",
                             "unaffected", "12.1.0;12.0.0;11.6.1;11.6.0_HF5;11.5.4;11.5.3_HF2;11.4.1_HF9;11.2.1_HF15;");

check_f5["GTM"] = make_array("affected",   "11.0.0-11.6.0;10.1.0-10.2.4;",
                             "unaffected", "11.6.1;11.6.0_HF5;11.5.4;11.5.3_HF2;11.4.1_HF9;11.2.1_HF15;");

check_f5["LC"]  = make_array("affected",   "11.0.0-11.6.0;10.1.0-10.2.4;",
                             "unaffected", "12.1.0;12.0.0;11.6.1;11.6.0_HF5;11.5.4;11.5.3_HF2;11.4.1_HF9;11.2.1_HF15;");

check_f5["PEM"] = make_array("affected",   "11.3.0-11.6.0;",
                             "unaffected", "12.1.0;12.0.0;11.6.1;11.6.0_HF5;11.5.4;11.5.3_HF2;11.4.1_HF9;");

check_f5["PSM"] = make_array("affected",   "11.0.0-11.4.1;10.1.0-10.2.4;",
                             "unaffected", "11.2.1_HF15;");

check_f5["WAM"] = make_array("affected",   "11.0.0-11.3.0;10.1.0-10.2.4;",
                             "unaffected", "11.2.1_HF15;");

check_f5["WOM"] = make_array("affected",   "11.0.0-11.3.0;10.1.0-10.2.4;",
                             "unaffected", "11.2.1_HF15;");

if (report = f5_is_vulnerable(ca: check_f5, version: version)) {
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
