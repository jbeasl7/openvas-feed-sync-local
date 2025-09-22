# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143920");
  script_version("2023-08-09T05:05:14+0000");
  script_tag(name:"last_modification", value:"2023-08-09 05:05:14 +0000 (Wed, 09 Aug 2023)");
  script_tag(name:"creation_date", value:"2020-05-18 02:42:21 +0000 (Mon, 18 May 2020)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2020-12440");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("nginx <= 1.18.0 HTTP Request Smuggling Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Web Servers");

  script_tag(name:"summary", value:"Deprecated since the CVE has been rejected: 'Reason: This candidate was
  withdrawn. Further investigation showed that it was not a security issue.'

  nginx allows an HTTP request smuggling attack that can lead to cache
  poisoning, credential hijacking, or security bypass.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"nginx version 1.18.0 and prior.");

  script_tag(name:"solution", value:"No solution was made available by the vendor. General solution options
  are to upgrade to a newer release, disable respective features, remove the product or replace the product by
  another one.");

  script_xref(name:"URL", value:"https://gist.github.com/Glassware123/1023720bf4787375a04f32a0c12e956a");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
