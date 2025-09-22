# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833310");
  script_cve_id("CVE-2024-25126", "CVE-2024-26141", "CVE-2024-26146");
  script_tag(name:"creation_date", value:"2024-03-08 02:01:02 +0000 (Fri, 08 Mar 2024)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-02-14 15:51:42 +0000 (Fri, 14 Feb 2025)");

  script_name("openSUSE Security Advisory (SUSE-SU-2024:0765-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:0765-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20240765-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220239");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220242");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220248");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2024-March/018091.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'rubygem-rack' package(s) announced via the SUSE-SU-2024:0765-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for rubygem-rack fixes the following issues:

- CVE-2024-25126: Fixed a denial-of-service vulnerability in Rack Content-Type parsing (bsc#1220239).
- CVE-2024-26141: Fixed a denial-of-service vulnerability in Range request header parsing (bsc#1220242).
- CVE-2024-26146: Fixed a denial-of-service vulnerability in Rack headers parsing routine (bsc#1220248).");

  script_tag(name:"affected", value:"'rubygem-rack' package(s) on openSUSE Leap 15.5.");

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

  if(!isnull(res = isrpmvuln(pkg:"ruby2.5-rubygem-rack", rpm:"ruby2.5-rubygem-rack~2.0.8~150000.3.21.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.5-rubygem-rack-doc", rpm:"ruby2.5-rubygem-rack-doc~2.0.8~150000.3.21.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.5-rubygem-rack-testsuite", rpm:"ruby2.5-rubygem-rack-testsuite~2.0.8~150000.3.21.2", rls:"openSUSELeap15.5"))) {
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
