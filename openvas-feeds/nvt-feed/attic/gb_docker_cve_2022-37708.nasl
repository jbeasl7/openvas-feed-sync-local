# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.104559");
  script_version("2024-02-28T14:37:42+0000");
  script_tag(name:"last_modification", value:"2024-02-28 14:37:42 +0000 (Wed, 28 Feb 2024)");
  script_tag(name:"creation_date", value:"2023-02-24 08:36:18 +0000 (Fri, 24 Feb 2023)");
  script_tag(name:"cvss_base", value:"6.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:C/I:C/A:N");

  script_cve_id("CVE-2022-37708");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("Docker <= 20.10.15 build fd8262 Insecure Permissions Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");

  script_tag(name:"summary", value:"Docker is prone to an insecure permissions vulnerability.

  NOTE: The CVE has been set to REJECTED. Reason: It was withdrawn by its CNA. Further investigation
  showed that it was not a security issue. Therefore this VT has been deprecated.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Unauthorized users outside the Docker container can access any
  files within the Docker container.");

  script_tag(name:"affected", value:"Docker version 20.10.15 build fd8262 and prior.");

  script_tag(name:"solution", value:"No solution is required.

  Note: Further investigation showed that it was not a security issue.");

  script_xref(name:"URL", value:"https://github.com/advisories/GHSA-p779-957q-8gq3");
  script_xref(name:"URL", value:"https://github.com/thekevinday/docker_lightman_exploit");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
