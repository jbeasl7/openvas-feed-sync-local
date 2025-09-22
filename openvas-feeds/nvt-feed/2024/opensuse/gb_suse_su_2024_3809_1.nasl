# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856646");
  script_cve_id("CVE-2024-34155", "CVE-2024-34156", "CVE-2024-34158");
  script_tag(name:"creation_date", value:"2024-10-31 05:01:58 +0000 (Thu, 31 Oct 2024)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("openSUSE Security Advisory (SUSE-SU-2024:3809-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:3809-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20243809-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230252");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230253");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230254");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2024-October/019717.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'go1.21-openssl' package(s) announced via the SUSE-SU-2024:3809-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for go1.21-openssl fixes the following issues:

- CVE-2024-34158: Fixed stack exhaustion in Parse in go/build/constraint (bsc#1230254).
- CVE-2024-34156: Fixed stack exhaustion in Decoder.Decode in encoding/gob (bsc#1230253).
- CVE-2024-34155: Fixed stack exhaustion in all Parse* functions (bsc#1230252).

- Update to version 1.21.13.3 cut from the go1.21-fips-release (jsc#SLE-18320).");

  script_tag(name:"affected", value:"'go1.21-openssl' package(s) on openSUSE Leap 15.5.");

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

  if(!isnull(res = isrpmvuln(pkg:"go1.21-openssl", rpm:"go1.21-openssl~1.21.13.4~150000.1.14.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.21-openssl-doc", rpm:"go1.21-openssl-doc~1.21.13.4~150000.1.14.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.21-openssl-race", rpm:"go1.21-openssl-race~1.21.13.4~150000.1.14.1", rls:"openSUSELeap15.5"))) {
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
