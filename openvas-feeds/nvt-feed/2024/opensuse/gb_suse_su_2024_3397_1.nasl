# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856507");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2023-22656", "CVE-2023-45221", "CVE-2023-47169", "CVE-2023-47282", "CVE-2023-48368");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"creation_date", value:"2024-09-26 04:01:39 +0000 (Thu, 26 Sep 2024)");
  script_name("openSUSE: Security Advisory for libmfx (SUSE-SU-2024:3397-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.4");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:3397-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/W7N4CTS374KAK733BZWVZWH45YRC67EJ");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libmfx'
  package(s) announced via the SUSE-SU-2024:3397-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libmfx fixes the following issues:

  * CVE-2023-48368: Fixed an improper input validation. (bsc#1226897)

  * CVE-2023-45221: Fixed an improper buffer restrictions. (bsc#1226898)

  * CVE-2023-22656: Fixed an out-of-bounds read. (bsc#1226899)

  * CVE-2023-47282: Fixed an out-of-bounds write. (bsc#1226900)

  * CVE-2023-47169: Fixed an improper buffer restrictions. (bsc#1226901)");

  script_tag(name:"affected", value:"'libmfx' package(s) on openSUSE Leap 15.4.");

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

if(release == "openSUSELeap15.4") {

  if(!isnull(res = isrpmvuln(pkg:"libmfx-debugsource", rpm:"libmfx-debugsource~21.3.4~150400.3.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmfx1-debuginfo", rpm:"libmfx1-debuginfo~21.3.4~150400.3.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmfx1", rpm:"libmfx1~21.3.4~150400.3.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmfx", rpm:"libmfx~21.3.4~150400.3.5.1", rls:"openSUSELeap15.4"))) {
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