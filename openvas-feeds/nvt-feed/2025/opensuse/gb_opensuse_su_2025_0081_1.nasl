# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.1.2025.0081.1");
  script_cve_id("CVE-2023-30536", "CVE-2024-2961", "CVE-2025-24529", "CVE-2025-24530");
  script_tag(name:"creation_date", value:"2025-03-05 04:07:01 +0000 (Wed, 05 Mar 2025)");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-05-01 16:38:35 +0000 (Mon, 01 May 2023)");

  script_name("openSUSE Security Advisory (openSUSE-SU-2025:0081-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2025:0081-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/472PX6IZ26ALBE66YKBJD3XTN7M34U4L/");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222992");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1236311");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1236312");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1238159");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'phpMyAdmin' package(s) announced via the openSUSE-SU-2025:0081-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for phpMyAdmin fixes the following issues:

Update to version 5.2.2:

- CVE-2025-24530: XSS in the 'Check Tables' feature (bsc#1236312).
- CVE-2025-24529: XSS in the 'Insert' tab (bsc#1236311).
- CVE-2024-2961: glibc/iconv: out-of-bounds writes when writing escape sequences (bsc#1222992).
- CVE-2023-30536: slim/psr7: improper header validation (bsc#1238159).");

  script_tag(name:"affected", value:"'phpMyAdmin' package(s) on openSUSE Leap 15.6.");

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

if(release == "openSUSELeap15.6") {

  if(!isnull(res = isrpmvuln(pkg:"phpMyAdmin", rpm:"phpMyAdmin~5.2.2~bp156.4.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"phpMyAdmin-apache", rpm:"phpMyAdmin-apache~5.2.2~bp156.4.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"phpMyAdmin-lang", rpm:"phpMyAdmin-lang~5.2.2~bp156.4.3.1", rls:"openSUSELeap15.6"))) {
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
