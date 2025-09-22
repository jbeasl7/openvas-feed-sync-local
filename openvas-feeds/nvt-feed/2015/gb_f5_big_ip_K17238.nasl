# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/h:f5:big-ip";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105358");
  script_cve_id("CVE-2015-5380");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_version("2024-05-29T05:05:18+0000");

  script_name("F5 BIG-IP - Node.js vulnerability CVE-2015-5380");

  script_xref(name:"URL", value:"https://my.f5.com/manage/s/article/K17238");

  script_tag(name:"impact", value:"For the f5-rest-node package on both the BIG-IP and BIG-IQ systems: A locally authenticated attacker with access to the command line may be able to cause a partial denial-of-service (DoS) to the system through exploitation of this issue.For the BIG-IQ UI node package: A remote attacker may be able to cause a denial of service (DoS) to the system through exploitation of this issue.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The Utf8DecoderBase::WriteUtf16Slow function in unicode-decoder.cc in Google V8, as used in Node.js before 0.12.6, io.js before 1.8.3 and 2.x before 2.3.3, and other products, does not verify that there is memory available for a UTF-16 surrogate pair, which allows remote attackers to cause a denial of service (memory corruption) or possibly have unspecified other impact via a crafted byte sequence. (CVE-2015-5380)");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"summary", value:"The remote host is missing a security patch.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"2024-05-29 05:05:18 +0000 (Wed, 29 May 2024)");
  script_tag(name:"creation_date", value:"2015-09-18 14:31:27 +0200 (Fri, 18 Sep 2015)");
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

check_f5["LTM"] = make_array("affected",   "12.0.0;11.5.0-11.6.0;",
                             "unaffected", "12.1.0;12.0.0_HF3;11.6.1;11.0.0-11.4.1;10.1.0-10.2.4;");

check_f5["AAM"] = make_array("affected",   "12.0.0;11.5.0-11.6.0;",
                             "unaffected", "12.1.0;12.0.0_HF3;11.6.1;11.4.0-11.4.1;");

check_f5["AFM"] = make_array("affected",   "12.0.0;11.5.0-11.6.0;",
                             "unaffected", "12.1.0;12.0.0_HF3;11.6.1;11.3.0-11.4.1;");

check_f5["AVR"] = make_array("affected",   "12.0.0;11.5.0-11.6.0;",
                             "unaffected", "12.1.0;12.0.0_HF3;11.6.1;11.0.0-11.4.1;");

check_f5["APM"] = make_array("affected",   "12.0.0;11.5.0-11.6.0;",
                             "unaffected", "12.1.0;12.0.0_HF3;11.6.1;11.0.0-11.4.1;10.1.0-10.2.4;");

check_f5["ASM"] = make_array("affected",   "12.0.0;11.5.0-11.6.0;",
                             "unaffected", "12.1.0;12.0.0_HF3;11.6.1;11.0.0-11.4.1;10.1.0-10.2.4;");

check_f5["GTM"] = make_array("affected",   "11.5.0-11.6.0;",
                             "unaffected", "11.6.1;11.0.0-11.4.1;10.1.0-10.2.4;");

check_f5["LC"]  = make_array("affected",   "12.0.0;11.5.0-11.6.0;",
                             "unaffected", "12.1.0;12.0.0_HF3;11.6.1;11.0.0-11.4.1;10.1.0-10.2.4;");

check_f5["PEM"] = make_array("affected",   "12.0.0;11.5.0-11.6.0;",
                             "unaffected", "12.1.0;12.0.0_HF3;11.6.1;11.3.0-11.4.1;");

if (report = f5_is_vulnerable(ca: check_f5, version: version)) {
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
