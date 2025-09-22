# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2024.0970.1");
  script_cve_id("CVE-2020-18442", "CVE-2020-18770");
  script_tag(name:"creation_date", value:"2025-02-25 14:26:30 +0000 (Tue, 25 Feb 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-08-25 20:42:53 +0000 (Fri, 25 Aug 2023)");

  script_name("openSUSE Security Advisory (SUSE-SU-2024:0970-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:0970-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20240970-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1154002");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1187526");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1214577");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2024-March/018191.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'zziplib' package(s) announced via the SUSE-SU-2024:0970-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for zziplib fixes the following issues:

Security issue fixed:

- CVE-2020-18442: Fixed infinite loop in zzip_file_read() as used in unzzip_cat_file() (bsc#1187526).
- CVE-2020-18770: Fixed denial-of-service in function zzip_disk_entry_to_file_header in mmapped.c (bsc#1214577).

Non-security issue fixed:

- Implement an error message with a condition by checking the return value of a function call. (bsc#1154002)");

  script_tag(name:"affected", value:"'zziplib' package(s) on openSUSE Leap 15.5.");

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

  if(!isnull(res = isrpmvuln(pkg:"libzzip-0-13", rpm:"libzzip-0-13~0.13.69~150000.3.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libzzip-0-13-32bit", rpm:"libzzip-0-13-32bit~0.13.69~150000.3.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zziplib-devel", rpm:"zziplib-devel~0.13.69~150000.3.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zziplib-devel-32bit", rpm:"zziplib-devel-32bit~0.13.69~150000.3.17.1", rls:"openSUSELeap15.5"))) {
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
