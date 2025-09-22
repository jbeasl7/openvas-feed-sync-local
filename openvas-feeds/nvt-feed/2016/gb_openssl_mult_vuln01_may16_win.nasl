# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:openssl:openssl";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807569");
  script_version("2024-02-09T05:06:25+0000");
  script_cve_id("CVE-2016-2176", "CVE-2016-2109", "CVE-2016-2106", "CVE-2016-2107",
                "CVE-2016-2105");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2024-02-09 05:06:25 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-07-19 01:29:00 +0000 (Thu, 19 Jul 2018)");
  script_tag(name:"creation_date", value:"2016-05-02 12:46:24 +0530 (Mon, 02 May 2016)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("OpenSSL Multiple Vulnerabilities -01 (May 2016) - Windows");

  script_tag(name:"summary", value:"OpenSSL is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - An integer overflow in the EVP_EncryptUpdate function in crypto/evp/evp_enc.c
  script in OpenSSL.

  - An integer overflow in the EVP_EncodeUpdate function in crypto/evp/encode.c
  script in OpenSSL.

  - An error in the 'asn1_d2i_read_bio' function in crypto/asn1/a_d2i_fp.c script
  in the ASN.1 BIO implementation in OpenSSL.

  - An error in 'X509_NAME_oneline' function in crypto/x509/x509_obj.c in OpenSSL.

  - A MITM attacker can use a padding oracle attack to decrypt traffic
  when the connection uses an AES CBC cipher and the server support AES-NI.");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote
  attacker to conduct mitm attack, gain access to potentially sensitive information,
  and cause denial of service condition.");

  script_tag(name:"affected", value:"OpenSSL versions 1.0.1 before 1.0.1t
  and 1.0.2 before 1.0.2h.");

  script_tag(name:"solution", value:"Upgrade to OpenSSL 1.0.1t or 1.0.2h or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.openssl.org/news/secadv/20160503.txt");
  script_xref(name:"URL", value:"https://mta.openssl.org/pipermail/openssl-announce/2016-April/000069.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("General");
  script_dependencies("gb_openssl_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("openssl/detected", "Host/runs_windows");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(isnull(port = get_app_port(cpe:CPE)))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(vers =~ "^1\.0\.1") {
  if(version_is_less(version:vers, test_version:"1.0.1t")) {
    fix = "1.0.1t";
    VULN = TRUE;
  }
}
else if(vers =~ "^1\.0\.2") {
  if(version_is_less(version:vers, test_version:"1.0.2h")) {
    fix = "1.0.2h";
    VULN = TRUE;
  }
}

if(VULN) {
  report = report_fixed_ver(installed_version:vers, fixed_version:fix, install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
