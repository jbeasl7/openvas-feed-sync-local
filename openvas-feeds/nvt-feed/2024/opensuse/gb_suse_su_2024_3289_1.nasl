# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856486");
  script_cve_id("CVE-2023-22656", "CVE-2023-45221", "CVE-2023-47169", "CVE-2023-47282", "CVE-2023-48368", "CVE-2023-50186");
  script_tag(name:"creation_date", value:"2024-09-19 04:00:27 +0000 (Thu, 19 Sep 2024)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-12-16 20:26:46 +0000 (Mon, 16 Dec 2024)");

  script_name("openSUSE Security Advisory (SUSE-SU-2024:3289-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:3289-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20243289-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218534");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219494");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223263");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226892");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226897");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226898");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226899");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226900");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226901");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2024-September/019443.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gstreamer-plugins-bad, libvpl' package(s) announced via the SUSE-SU-2024:3289-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for gstreamer-plugins-bad, libvpl fixes the following issues:

- Dropped support for libmfx to fix the following CVEs:
 * libmfx: improper input validation (CVE-2023-48368, bsc#1226897)
 * libmfx: improper buffer restrictions (CVE-2023-45221, bsc#1226898)
 * libmfx: out-of-bounds read (CVE-2023-22656, bsc#1226899)
 * libmfx: out-of-bounds write (CVE-2023-47282, bsc#1226900)
 * libmfx: improper buffer restrictions (CVE-2023-47169, bsc#1226901)

The libmfx dependency is replaced by libvpl.");

  script_tag(name:"affected", value:"'gstreamer-plugins-bad, libvpl' package(s) on openSUSE Leap 15.5.");

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

  if(!isnull(res = isrpmvuln(pkg:"libvpl", rpm:"libvpl~2023.0.0~150500.3.2.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvpl-devel", rpm:"libvpl-devel~2023.0.0~150500.3.2.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvpl2", rpm:"libvpl2~2023.0.0~150500.3.2.1", rls:"openSUSELeap15.5"))) {
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
