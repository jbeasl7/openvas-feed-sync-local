# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2025.02545.1");
  script_cve_id("CVE-2025-30749", "CVE-2025-30754", "CVE-2025-30761", "CVE-2025-50059");
  script_tag(name:"creation_date", value:"2025-07-31 04:20:33 +0000 (Thu, 31 Jul 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-07-15 20:15:40 +0000 (Tue, 15 Jul 2025)");

  script_name("openSUSE Security Advisory (SUSE-SU-2025:02545-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:02545-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-202502545-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246575");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246580");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246595");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246598");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-July/040956.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java-1_8_0-openj9' package(s) announced via the SUSE-SU-2025:02545-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for java-1_8_0-openj9 fixes the following issues:

Update to OpenJDK 8u462 build 08 with OpenJ9 0.53.0 virtual machine:

- CVE-2025-30749: several scenarios can lead to heap corruption (Oracle CPU 2025-07) (bsc#1246595)
- CVE-2025-30754: incomplete handshake may lead to weakening TLS protections (Oracle CPU 2025-07) (bsc#1246598)
- CVE-2025-30761: Improve scripting supports (Oracle CPU 2025-07) (bsc#1246580)
- CVE-2025-50059: Improve HTTP client header handling (Oracle CPU 2025-07) (bsc#1246575)");

  script_tag(name:"affected", value:"'java-1_8_0-openj9' package(s) on openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openj9", rpm:"java-1_8_0-openj9~1.8.0.462~150200.3.57.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openj9-accessibility", rpm:"java-1_8_0-openj9-accessibility~1.8.0.462~150200.3.57.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openj9-demo", rpm:"java-1_8_0-openj9-demo~1.8.0.462~150200.3.57.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openj9-devel", rpm:"java-1_8_0-openj9-devel~1.8.0.462~150200.3.57.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openj9-headless", rpm:"java-1_8_0-openj9-headless~1.8.0.462~150200.3.57.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openj9-javadoc", rpm:"java-1_8_0-openj9-javadoc~1.8.0.462~150200.3.57.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_8_0-openj9-src", rpm:"java-1_8_0-openj9-src~1.8.0.462~150200.3.57.1", rls:"openSUSELeap15.6"))) {
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
