# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:hp:comware";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106412");
  script_version("2025-09-09T14:09:45+0000");
  script_tag(name:"last_modification", value:"2025-09-09 14:09:45 +0000 (Tue, 09 Sep 2025)");
  script_tag(name:"creation_date", value:"2016-11-25 13:11:53 +0700 (Fri, 25 Nov 2016)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-11-23 19:48:00 +0000 (Mon, 23 Nov 2020)");

  script_cve_id("CVE-2004-2761", "CVE-2013-2566", "CVE-2015-2808");

  script_tag(name:"qod_type", value:"remote_active");

  script_tag(name:"solution_type", value:"Mitigation");

  script_name("HPE Network Products Multiple Remote Vulnerabilities (HPSBHF03673)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("General");
  script_dependencies("gb_hp_comware_platform_snmp_detect.nasl",
                      "gb_hp_comware_platform_ssh_banner_detect.nasl",
                      "gb_ssl_tls_ciphers_gathering.nasl");
  script_mandatory_keys("hp/comware_device", "ssl_tls/port",
                        "ssl_tls/ciphers/supported_ciphers");

  script_tag(name:"summary", value:"HPE Comware 5 and Comware 7 network products are prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if RC2 and RC4 ciphers are enabled on the SSL ports.");

  script_tag(name:"insight", value:"Security vulnerabilities in MD5 message digest algorithm and RC4
  ciphersuite could potentially impact HPE Comware 5 and Comware 7 network products using SSL/TLS. These
  vulnerabilities could be exploited remotely to conduct spoofing attacks and plaintext recovery attacks resulting
  in disclosure of information.");

  script_tag(name:"impact", value:"An attacker may conduct spoofing and plaintext recovery attacks resulting
  in information disclosure.");

  script_tag(name:"affected", value:"Comware 5 and Comware 7 Products: All versions.");

  script_tag(name:"solution", value:"For mitigation HPE recommends disabling RC2 and RC4 ciphers.");

  script_xref(name:"URL", value:"https://support.hpe.com/hpesc/public/docDisplay?docId=c05336888&docLocale=en_US");

  exit(0);
}

include("host_details.inc");
include("ssl_funcs.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version =~ "^[57]") {
  port = tls_ssl_get_port();
  if (!port)
    exit(0);

  weakciphers = get_kb_list("ssl_tls/ciphers/*/" + port + "/supported_ciphers");
  if (weakciphers =~ "_RC[24]_") {
    security_message(port: port);
    exit(0);
  }
}

exit(0);
