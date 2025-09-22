# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833249");
  script_cve_id("CVE-2023-4408", "CVE-2023-50387", "CVE-2023-50868", "CVE-2023-5517", "CVE-2023-5679", "CVE-2023-6516");
  script_tag(name:"creation_date", value:"2024-03-04 12:50:15 +0000 (Mon, 04 Mar 2024)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-13 14:15:46 +0000 (Tue, 13 Feb 2024)");

  script_name("openSUSE Security Advisory (SUSE-SU-2024:0574-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:0574-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20240574-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219823");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219826");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219851");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219852");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219853");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219854");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2024-February/017984.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'bind' package(s) announced via the SUSE-SU-2024:0574-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for bind fixes the following issues:

Update to release 9.16.48:

- CVE-2023-50387: Fixed a denial-of-service caused by DNS messages containing a lot of DNSSEC signatures (bsc#1219823).
- CVE-2023-50868: Fixed a denial-of-service caused by NSEC3 closest encloser proof (bsc#1219826).
- CVE-2023-4408: Fixed a denial-of-service caused by DNS messages with many different names (bsc#1219851).
- CVE-2023-5517: Fixed a possible crash when nxdomain-redirect was enabled (bsc#1219852).
- CVE-2023-5679: Fixed a possible crash when bad interaction between DNS64 and serve-stale, when both of these features are enabled (bsc#1219853).
- CVE-2023-6516: Fixed excessive memory consumption when continuously trigger the cache database maintenance (bsc#1219854).");

  script_tag(name:"affected", value:"'bind' package(s) on openSUSE Leap 15.5.");

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

if(release == "openSUSELeap15.5") {

  if(!isnull(res = isrpmvuln(pkg:"bind", rpm:"bind~9.16.48~150500.8.16.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-doc", rpm:"bind-doc~9.16.48~150500.8.16.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-utils", rpm:"bind-utils~9.16.48~150500.8.16.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-bind", rpm:"python3-bind~9.16.48~150500.8.16.1", rls:"openSUSELeap15.5"))) {
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
