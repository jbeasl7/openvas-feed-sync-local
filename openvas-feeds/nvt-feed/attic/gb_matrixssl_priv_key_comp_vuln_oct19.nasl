# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.126298");
  script_version("2025-01-17T05:37:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 05:37:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2023-01-13 10:31:52 +0000 (Fri, 13 Jan 2023)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-08 20:24:00 +0000 (Tue, 08 Oct 2019)");

  script_cve_id("CVE-2019-13629");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MatrixSSL < 4.2.2 Private Key Computation Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");

  script_tag(name:"summary", value:"MatrixSSL is prone to a private key computation
  vulnerability.

  This VT has been deprecated and merged into the VT 'MatrixSSL < 4.2.2 Multiple Vulnerabilities' (OID:
  1.3.6.1.4.1.25623.1.0.142693).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"MatrixSSL contains a timing side channel in ECDSA signature
  generation. This allows a local or a remote attacker to measure the duration of hundreds to
  thousands of signing operations, to compute the private key used. The issue occurs because
  crypto/pubkey/ecc_math.c scalar multiplication leaks the bit length of the scalar.");

  script_tag(name:"affected", value:"MatrixSSL prior to version 4.2.2.");

  script_tag(name:"solution", value:"Update to version 4.2.2 or later.");

  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2019/10/02/2");
  script_xref(name:"URL", value:"https://github.com/matrixssl/matrixssl/releases/tag/4-2-2-open");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
