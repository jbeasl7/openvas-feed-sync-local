# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108775");
  script_version("2024-06-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-06-13 05:05:46 +0000 (Thu, 13 Jun 2024)");
  script_tag(name:"creation_date", value:"2020-06-05 08:17:40 +0000 (Fri, 05 Jun 2020)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-12-08 18:40:00 +0000 (Fri, 08 Dec 2017)");

  script_cve_id("CVE-2017-8213");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Huawei Data Communication: DoS Vulnerability in TLS of Some Huawei Products (huawei-sa-20170705-01-tls)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Huawei");

  script_tag(name:"summary", value:"There is a denial of service (DoS) vulnerability in some huawei products when handle TLS and DTLS handshake with certificate.

  This VT has been deprecated and is therefore no longer functional.");

  script_tag(name:"insight", value:"There is a denial of service (DoS) vulnerability in some huawei products when handle TLS and DTLS handshake with certificate. Due to the insufficient validation of PKI certificates, remote attackers could exploit this vulnerability to crash the TLS module. (Vulnerability ID: HWPSIRT-2017-03121)This vulnerability has been assigned a Common Vulnerabilities and Exposures (CVE) ID: CVE-2017-8213.Huawei has released software updates to fix this vulnerability. This advisory is available in the linked references.");

  script_tag(name:"impact", value:"Successful exploitation of the vulnerability allows attackers to crash TLS module.");

  script_tag(name:"affected", value:"SMC2.0 versions V100R003C10 V100R005C00SPC100 V100R005C00SPC101B001T V100R005C00SPC102 V100R005C00SPC103 V100R005C00SPC200 V100R005C00SPC201T V500R002C00 V500R002C00B002 V500R002C00SPC100 V500R002C00SPC100T V500R002C00SPC200 V500R002C00SPC200B005 V500R002C00SPC300 V500R002C00SPC300T V500R002C00SPC400T V500R002C00SPC500 V500R002C00SPC500T V500R002C00SPC600 V500R002C00SPC600T V500R002C00SPC601T V500R002C00SPC602T V500R002C00SPC603T V500R002C00SPC604T V500R002C00SPC700 V500R002C00SPC800 V500R002C00SPC900 V500R002C00SPCa00 V500R002C00SPCa00T V500R002C00SPCa01T V500R002C00SPCa02T V500R002C00SPCa03T V500R002C00T V600R006C00 V600R006C00SPC001T V600R006C00SPC002T V600R006C00SPC003T V600R006C00SPC060T V600R006C00SPC061T V600R006C00SPC100 V600R006C00SPC200 V600R006C00SPC200T V600R006C00SPC201T V600R006C00T

TE60 versions V600R006C00

eSpace 7910 versions V200R003C00 V200R003C30");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_xref(name:"URL", value:"https://www.huawei.com/en/psirt/security-advisories/huawei-sa-20170705-01-tls-en");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66); # nb: Unknown device (no VRP), no public vendor advisory or general inconsistent / broken data
