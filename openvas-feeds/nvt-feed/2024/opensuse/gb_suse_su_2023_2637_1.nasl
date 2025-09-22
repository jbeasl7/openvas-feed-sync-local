# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833379");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2022-31394", "CVE-2023-1521");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-03-02 16:05:03 +0000 (Thu, 02 Mar 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 12:52:14 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for sccache (SUSE-SU-2023:2637-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.3");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:2637-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/HIEQ5HNSWXIPFXEZDWSQ3T36BWEYSQXG");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'sccache'
  package(s) announced via the SUSE-SU-2023:2637-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for sccache fixes the following issues:

  * CVE-2023-1521: Fixed possible code injection via LD_PRELOAD to sccache
      server (bsc#1212407).

  * CVE-2022-31394: Fixed a denial-of-service vulnerability via header list size
      (bsc#1208553).

  ##");

  script_tag(name:"affected", value:"'sccache' package(s) on openSUSE Leap 15.3.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

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

if(release == "openSUSELeap15.3") {

  if(!isnull(res = isrpmvuln(pkg:"sccache-debuginfo", rpm:"sccache-debuginfo~0.4.1~18~150300.7.12.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sccache", rpm:"sccache~0.4.1~18~150300.7.12.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sccache-debuginfo", rpm:"sccache-debuginfo~0.4.1~18~150300.7.12.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sccache", rpm:"sccache~0.4.1~18~150300.7.12.1", rls:"openSUSELeap15.3"))) {
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