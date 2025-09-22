# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2025.0980.1");
  script_cve_id("CVE-2024-41110", "CVE-2024-45337", "CVE-2024-45338", "CVE-2025-22869", "CVE-2025-22870", "CVE-2025-27144");
  script_tag(name:"creation_date", value:"2025-03-24 04:06:35 +0000 (Mon, 24 Mar 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("openSUSE Security Advisory (SUSE-SU-2025:0980-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:0980-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-20250980-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228324");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234595");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234794");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237679");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1238611");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1239341");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2025-March/020574.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'apptainer' package(s) announced via the SUSE-SU-2025:0980-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for apptainer fixes the following issues:

- CVE-2025-27144: Fixed Denial of Service in Go JOSE's Parsing (bsc#1237679).
- CVE-2024-45338: Fixed denial of service due to non-linear parsing of case-insensitive content (bsc#1234794).
- CVE-2024-45337: Fixed Misuse of ServerConfig.PublicKeyCallback may cause authorization bypass in golang.org/x/crypto (bsc#1234595).
- CVE-2025-22870: Fixed proxy bypass using IPv6 zone IDs (bsc#1238611).
- CVE-2025-22869: Fixed Denial of Service in the Key Exchange of golang.org/x/crypto/ssh (bsc#1239341).
- CVE-2024-41110: Fixed Authz zero length regression (bsc#1228324).");

  script_tag(name:"affected", value:"'apptainer' package(s) on openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"apptainer", rpm:"apptainer~1.3.6~150600.4.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apptainer-leap", rpm:"apptainer-leap~1.3.6~150600.4.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apptainer-sle15_5", rpm:"apptainer-sle15_5~1.3.6~150600.4.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apptainer-sle15_6", rpm:"apptainer-sle15_6~1.3.6~150600.4.9.1", rls:"openSUSELeap15.6"))) {
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
