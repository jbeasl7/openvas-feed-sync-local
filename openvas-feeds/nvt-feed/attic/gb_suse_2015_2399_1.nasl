# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.851151");
  script_version("2024-01-24T14:38:46+0000");
  script_tag(name:"last_modification", value:"2024-01-24 14:38:46 +0000 (Wed, 24 Jan 2024)");
  script_tag(name:"creation_date", value:"2015-12-31 05:12:48 +0100 (Thu, 31 Dec 2015)");
  script_cve_id("CVE-2015-8370");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("SUSE: Security Advisory for grub2 (SUSE-SU-2015:2399-1)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'grub2'
  package(s) announced via the referenced advisory.

  This VT has been deprecated as a duplicate of the VT 'SUSE: Security Advisory
  (SUSE-SU-2015:2399-1)' (OID: 1.3.6.1.4.1.25623.1.1.4.2015.2399.1).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for grub2 provides the following fixes and enhancements:

  Security issue fixed:

  - Fix buffer overflows when reading username and password. (bsc#956631,
  CVE-2015-8370)

  Non security issues fixed:

  - Expand list of grub.cfg search path in PV Xen guests for systems
  installed
  on btrfs snapshots. (bsc#946148, bsc#952539)

  - Add --image switch to force zipl update to specific kernel. (bsc#928131)

  - Do not use shim lock protocol for reading PE header as it won't be
  available when secure boot is disabled. (bsc#943380)

  - Make firmware flaw condition be more precisely detected and add debug
  message for the case.");

  script_tag(name:"affected", value:"grub2 on SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Desktop 12");

  script_tag(name:"solution", value:"Please install the updated package(s).");
  script_xref(name:"SUSE-SU", value:"2015:2399-1");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
