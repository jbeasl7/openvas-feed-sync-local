# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2025.01713.1");
  script_tag(name:"creation_date", value:"2025-05-29 04:08:27 +0000 (Thu, 29 May 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("openSUSE Security Advisory (SUSE-SU-2025:01713-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:01713-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-202501713-1.html");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2025-May/020907.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'govulncheck-vulndb' package(s) announced via the SUSE-SU-2025:01713-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for govulncheck-vulndb fixes the following issues:

- Update to version 0.0.20250523T151856 2025-05-23T15:18:56Z (jsc#PED-11136)
 * GO-2025-3699
 * GO-2025-3690
 * GO-2025-3691
 * GO-2025-3692
 * GO-2025-3693
 * GO-2025-3694
 * GO-2025-3696
 * GO-2025-3697
 * GO-2025-3698
 * GO-2025-3699
 * GO-2025-3700
 * GO-2025-3701
 * GO-2025-3702
 * GO-2025-3703

- Update to version 0.0.20250522T165031 2025-05-22T16:50:31Z (jsc#PED-11136)
 * GO-2025-3695

- Update to version 0.0.20250520T172319 2025-05-20T17:23:19Z (jsc#PED-11136)
 * GO-2025-3664");

  script_tag(name:"affected", value:"'govulncheck-vulndb' package(s) on openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"govulncheck-vulndb", rpm:"govulncheck-vulndb~0.0.20250523T151856~150000.1.77.1", rls:"openSUSELeap15.6"))) {
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
