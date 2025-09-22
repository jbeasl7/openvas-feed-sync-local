# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2024.2816.1");
  script_cve_id("CVE-2024-41989", "CVE-2024-41990", "CVE-2024-41991", "CVE-2024-42005");
  script_tag(name:"creation_date", value:"2025-02-25 14:26:30 +0000 (Tue, 25 Feb 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-08-07 18:35:05 +0000 (Wed, 07 Aug 2024)");

  script_name("openSUSE Security Advisory (SUSE-SU-2024:2816-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:2816-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20242816-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228629");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228630");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228631");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228632");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2024-August/019140.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-Django' package(s) announced via the SUSE-SU-2024:2816-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for python-Django fixes the following issues:

- CVE-2024-42005: Fixed SQL injection in QuerySet.values() and values_list() (bsc#1228629)
- CVE-2024-41989: Fixed Memory exhaustion in django.utils.numberformat.floatformat() (bsc#1228630)
- CVE-2024-41990: Fixed denial-of-service vulnerability in django.utils.html.urlize() (bsc#1228631)
- CVE-2024-41991: Fixed another denial-of-service vulnerability in django.utils.html.urlize() (bsc#1228632)");

  script_tag(name:"affected", value:"'python-Django' package(s) on openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"python311-Django", rpm:"python311-Django~4.2.11~150600.3.6.1", rls:"openSUSELeap15.6"))) {
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
