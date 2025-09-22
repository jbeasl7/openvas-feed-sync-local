# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833634");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2022-33972");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:M/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-03-06 19:43:51 +0000 (Mon, 06 Mar 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 07:37:16 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for ucode (SUSE-SU-2023:2243-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:2243-2");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/2YZPI25JUXCC2KHUTBYEM5GXFR3ZNZXD");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ucode'
  package(s) announced via the SUSE-SU-2023:2243-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for ucode-intel fixes the following issues:

  * Updated to Intel CPU Microcode 20230512 release. (bsc#1211382).

  * Updated Platforms  Processor  Stepping  F-M-S/PI  Old Ver  New Ver

  Description truncated. Please see the references for more information.");
  script_tag(name:"affected", value:"'ucode' package(s) on openSUSE Leap 15.5");
  script_tag(name:"solution", value:"Please install the updated package(s)");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "openSUSELeap15.5") {

  if(!isnull(res = isrpmvuln(pkg:"ucode-intel-20230512", rpm:"ucode-intel-20230512~150200.24.1##", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ucode-intel-20230512", rpm:"ucode-intel-20230512~150200.24.1##", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
