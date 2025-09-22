# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2025.0458.1");
  script_cve_id("CVE-2023-45288", "CVE-2024-6104");
  script_tag(name:"creation_date", value:"2025-02-18 11:01:57 +0000 (Tue, 18 Feb 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-06-26 17:19:40 +0000 (Wed, 26 Jun 2024)");

  script_name("openSUSE Security Advisory (SUSE-SU-2025:0458-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:0458-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-20250458-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1227052");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1236507");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2025-February/020326.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'podman' package(s) announced via the SUSE-SU-2025:0458-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for podman fixes the following issues:

- CVE-2024-6104: possible sensitive data exposure due to hashicorp/go-retryablehttp not sanitizing URLs when writing
 them to log files. (bsc#1227052)
- CVE-2023-45288: possible excessive CPU consumption due to no limit being set on the number of CONTINUATION frames
 read for an HTTP/2 request in golang.org/x/net/http2. (bsc#1236507)");

  script_tag(name:"affected", value:"'podman' package(s) on openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"podman", rpm:"podman~4.9.5~150500.3.34.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"podman-docker", rpm:"podman-docker~4.9.5~150500.3.34.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"podman-remote", rpm:"podman-remote~4.9.5~150500.3.34.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"podmansh", rpm:"podmansh~4.9.5~150500.3.34.2", rls:"openSUSELeap15.6"))) {
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
