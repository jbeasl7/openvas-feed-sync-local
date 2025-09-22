# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2017.2701.1");
  script_cve_id("CVE-2012-6702", "CVE-2015-3238", "CVE-2016-10156", "CVE-2016-1839", "CVE-2016-2037", "CVE-2016-4658", "CVE-2016-5011", "CVE-2016-5300", "CVE-2016-7055", "CVE-2016-9063", "CVE-2016-9318", "CVE-2016-9401", "CVE-2016-9586", "CVE-2016-9597", "CVE-2016-9840", "CVE-2016-9841", "CVE-2016-9842", "CVE-2016-9843", "CVE-2017-0663", "CVE-2017-1000100", "CVE-2017-1000101", "CVE-2017-1000366", "CVE-2017-10684", "CVE-2017-10685", "CVE-2017-11112", "CVE-2017-11113", "CVE-2017-2616", "CVE-2017-3731", "CVE-2017-3732", "CVE-2017-5969", "CVE-2017-6507", "CVE-2017-7375", "CVE-2017-7376", "CVE-2017-7407", "CVE-2017-7435", "CVE-2017-7436", "CVE-2017-7526", "CVE-2017-8872", "CVE-2017-9047", "CVE-2017-9048", "CVE-2017-9049", "CVE-2017-9050", "CVE-2017-9217", "CVE-2017-9233", "CVE-2017-9269", "CVE-2017-9287", "CVE-2017-9445");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:52 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:49+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:49 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-03-26 17:17:54 +0000 (Mon, 26 Mar 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2017:2701-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2017:2701-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2017/suse-su-20172701-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'SLES 12-SP2 Docker image' package(s) announced via the SUSE-SU-2017:2701-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise Server 12 SP2 container image has been updated to include security and stability fixes.
The following issues related to building of the container images have been fixed:
- Included krb5 package to avoid the inclusion of krb5-mini which gets
 selected as a dependency by the Build Service solver. (bsc#1056193)
A number of security issues that have been already fixed by updates released for SUSE Linux Enterprise Server 12 are now included in the base image. A package/CVE cross-reference is available below.
bash:
- CVE-2016-9401 expat:
- CVE-2012-6702
- CVE-2016-5300
- CVE-2016-9063
- CVE-2017-9233 curl:
- CVE-2016-9586
- CVE-2017-1000100
- CVE-2017-1000101
- CVE-2017-7407 glibc:
- CVE-2017-1000366 openssl:
- CVE-2017-3731
- CVE-2017-3732
- CVE-2016-7055 pam:
- CVE-2015-3238 apparmor:
- CVE-2017-6507 ncurses:
- CVE-2017-10684
- CVE-2017-10685
- CVE-2017-11112
- CVE-2017-11113 libgcrypt:
- CVE-2017-7526 libxml2:
- CVE-2016-1839
- CVE-2016-4658
- CVE-2016-9318
- CVE-2016-9597
- CVE-2017-0663
- CVE-2017-5969
- CVE-2017-7375
- CVE-2017-7376
- CVE-2017-8872
- CVE-2017-9047
- CVE-2017-9048
- CVE-2017-9049
- CVE-2017-9050 libzypp:
- CVE-2017-9269
- CVE-2017-7435
- CVE-2017-7436 openldap2:
- CVE-2017-9287 systemd:
- CVE-2016-10156
- CVE-2017-9217
- CVE-2017-9445 util-linux:
- CVE-2016-5011
- CVE-2017-2616 zlib:
- CVE-2016-9840
- CVE-2016-9841
- CVE-2016-9842
- CVE-2016-9843 zypper:
- CVE-2017-7436 Finally, the following packages received non-security fixes:
- binutils
- cpio
- cryptsetup
- cyrus-sasl
- dbus-1
- dirmngr
- e2fsprogs
- gpg2
- insserv-compat
- kmod
- libsolv
- libsemanage
- lvm2
- lua51
- netcfg
- procps
- sed
- sg3_utils
- shadow");

  script_tag(name:"affected", value:"'SLES 12-SP2 Docker image' package(s) on SUSE Linux Enterprise Module for Containers 12.");

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

if(release == "SLES12.0") {

  if(!isnull(res = isrpmvuln(pkg:"sles12sp2-docker-image", rpm:"sles12sp2-docker-image~1.0.2~20171006", rls:"SLES12.0"))) {
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
