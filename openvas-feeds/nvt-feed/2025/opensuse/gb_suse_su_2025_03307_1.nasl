# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2025.03307.1");
  script_cve_id("CVE-2024-12224", "CVE-2025-3416");
  script_tag(name:"creation_date", value:"2025-09-25 04:06:57 +0000 (Thu, 25 Sep 2025)");
  script_version("2025-09-25T05:39:09+0000");
  script_tag(name:"last_modification", value:"2025-09-25 05:39:09 +0000 (Thu, 25 Sep 2025)");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-04-08 19:15:53 +0000 (Tue, 08 Apr 2025)");

  script_name("openSUSE Security Advisory (SUSE-SU-2025:03307-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:03307-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-202503307-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1242618");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1243860");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-September/041813.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'sevctl' package(s) announced via the SUSE-SU-2025:03307-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for sevctl fixes the following issues:

- CVE-2024-12224: idna: Fixed improper validation of unsafe equivalence in punycode. (bsc#1243860)
- CVE-2025-3416: openssl: Fixed use-after-free in Md::fetch and Cipher::fetch (bsc#1242618)");

  script_tag(name:"affected", value:"'sevctl' package(s) on openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"sevctl", rpm:"sevctl~0.4.3~150600.4.3.1", rls:"openSUSELeap15.6"))) {
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
