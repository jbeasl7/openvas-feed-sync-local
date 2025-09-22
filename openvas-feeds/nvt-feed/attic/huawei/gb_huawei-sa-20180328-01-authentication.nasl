# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.112259");
  script_version("2024-06-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-06-13 05:05:46 +0000 (Thu, 13 Jun 2024)");
  script_tag(name:"creation_date", value:"2018-04-24 11:11:11 +0200 (Tue, 24 Apr 2018)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-05-23 14:26:00 +0000 (Wed, 23 May 2018)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2017-15327");

  script_name("Huawei Switches Improper Authorization Vulnerability (huawei-sa-20180328-01-authentication)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Huawei");

  script_tag(name:"summary", value:"There is an improper authorization vulnerability on Huawei switch products.
  The system incorrectly performs an authorization check when a normal user attempts to access certain information
  which is supposed to be accessed only by authenticated user.

  This VT has been deprecated as SA is already covered by following VT:

  - 'Huawei Data Communication: Improper Authorization Vulnerability on Huawei Switch Products (huawei-sa-20180328-01-authentication)' (OID:1.3.6.1.4.1.25623.1.0.107825)");

  script_tag(name:"vuldetect", value:"The script checks if the target host is an affected product that has a vulnerable
  firmware version installed.");

  script_tag(name:"impact", value:"Successful exploit could cause information disclosure.");

  script_tag(name:"affected", value:"The following Huawei Switch models and firmware versions are affected:

  Huawei Switch S12700 versions: V200R005C00, V200R006C00, V200R006C01, V200R007C00, V200R007C01, V200R007C20, V200R008C00, V200R008C06, V200R009C00, V200R010C00

  Huawei Switch S7700 versions: V200R001C00, V200R001C01, V200R002C00, V200R003C00, V200R005C00, V200R006C00, V200R006C01, V200R007C00, V200R007C01, V200R008C00, V200R008C06, V200R009C00, V200R010C00

  Huawei Switch S9700 versions: V200R001C00, V200R001C01, V200R002C00, V200R003C00, V200R005C00, V200R006C00, V200R006C01, V200R007C00, V200R007C01, V200R008C00, V200R009C00, V200R010C00");

  script_tag(name:"solution", value:"Update the software according to your product:

  Huawei Campus Switch S12700/S7700/S9700 fixed version: V200R010SPH002");

  script_xref(name:"URL", value:"https://www.huawei.com/en/psirt/security-advisories/huawei-sa-20180328-01-authentication-en");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
