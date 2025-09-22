# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.130065");
  script_cve_id("CVE-2015-4715", "CVE-2015-4717", "CVE-2015-4718");
  script_tag(name:"creation_date", value:"2015-10-15 07:42:17 +0000 (Thu, 15 Oct 2015)");
  script_version("2024-10-23T05:05:58+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:58 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-02-28 19:31:11 +0000 (Fri, 28 Feb 2020)");

  script_name("Mageia: Security Advisory (MGASA-2015-0314)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(4|5)");

  script_xref(name:"Advisory-ID", value:"MGASA-2015-0314");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0314.html");
  script_xref(name:"URL", value:"http://owncloud.org/changelog/");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=16491");
  script_xref(name:"URL", value:"https://owncloud.org/security/advisory/?id=oc-sa-2015-005");
  script_xref(name:"URL", value:"https://owncloud.org/security/advisory/?id=oc-sa-2015-007");
  script_xref(name:"URL", value:"https://owncloud.org/security/advisory/?id=oc-sa-2015-008");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'owncloud' package(s) announced via the MGASA-2015-0314 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"In ownCloud before 6.0.8 and 8.0.4, a bug in the SDK used to connect
ownCloud against the Dropbox server might allow the owner of 'Dropbox.com'
to gain access to any files on the ownCloud server if an external Dropbox
storage was mounted (CVE-2015-4715).

In ownCloud before 6.0.8 and 8.0.4, the sanitization component for
filenames was vulnerable to DoS when parsing specially crafted file names
passed via specific endpoints. Effectively this lead to a endless loop
filling the log file until the system is not anymore responsive
(CVE-2015-4717).

In ownCloud before 6.0.8 and 8.0.4, the external SMB storage of ownCloud
was not properly neutralizing all special elements which allows an
adversary to execute arbitrary SMB commands. This was caused by improperly
sanitizing the ',' character which is interpreted as command separator by
smbclient (the used software to connect to SMB shared by ownCloud).
Effectively this allows an attacker to gain access to any file on the
system or overwrite it, finally leading to a PHP code execution in the
case of ownCloud's config file (CVE-2015-4718).");

  script_tag(name:"affected", value:"'owncloud' package(s) on Mageia 4, Mageia 5.");

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

if(release == "MAGEIA4") {

  if(!isnull(res = isrpmvuln(pkg:"owncloud", rpm:"owncloud~6.0.9~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MAGEIA5") {

  if(!isnull(res = isrpmvuln(pkg:"owncloud", rpm:"owncloud~8.0.5~1.2.mga5", rls:"MAGEIA5"))) {
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
