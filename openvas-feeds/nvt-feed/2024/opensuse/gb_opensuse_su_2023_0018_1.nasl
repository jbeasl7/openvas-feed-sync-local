# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833035");
  script_version("2025-03-11T05:38:16+0000");
  script_cve_id("CVE-2021-44716", "CVE-2021-44717", "CVE-2022-39237");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2025-03-11 05:38:16 +0000 (Tue, 11 Mar 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-10-07 17:47:57 +0000 (Fri, 07 Oct 2022)");
  script_tag(name:"creation_date", value:"2024-03-04 07:33:17 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for apptainer (openSUSE-SU-2023:0018-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.4");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2023:0018-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/6WS5CSKKNIOV4MCZX36E2OGOEC5EKPNG");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'apptainer'
  package(s) announced via the openSUSE-SU-2023:0018-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for apptainer fixes the following issues:

     Updated to 1.1.2 which fixed CVE-2022-39237

  * CVE-2022-39237: The sif dependency included in Apptainer before this
         release does not verify that the hash algorithm(s) used are
         cryptographically secure when verifying digital signatures. This
         release updates to sif v2.8.1 which corrects this issue. See the
         linked advisory for references and a workaround.

     Updated to version 1.1.0

  * Change squash mounts to prefer to use squashfuse_ll instead of
         squashfuse, if available, for improved performance. squashfuse_ll is
         not available in factory.

  * Also, for even better parallel performance, include a patched
         multithreaded version of squashfuse_ll in

  * Imply adding ${prefix}/libexec/apptainer/bin to the binary path in
         apptainer.conf, which is used for searching for helper executables. It
         is implied as the first directory of $PATH if present (which is at the
         beginning of binary path by default) or just as the first directory if
         $PATH is not included in binary path. ${prefix}/libexec/apptainer/bin.

  * Add --unsquash action flag to temporarily convert a SIF file to a
         sandbox before running. In previous versions this was the default when
         running a SIF file without setuid or with fakeroot, but now the
         default is to instead mount with squashfuse.

  * Add --sparse flag to overlay create command to allow generation of a
         sparse ext3 overlay image.

  * Support for a custom hashbang in the %test section of an Apptainer
         recipe (akin to the runscript and start sections).
        Add additional hidden options to the action command for testing
         different fakeroot modes with --fakeroot: --ignore-subuid,

  - -ignore-fakeroot-command, and --ignore-userns.

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'apptainer' package(s) on openSUSE Leap 15.4.");

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

if(release == "openSUSELeap15.4") {

  if(!isnull(res = isrpmvuln(pkg:"apptainer", rpm:"apptainer~1.1.2~lp154.2.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apptainer-debuginfo", rpm:"apptainer-debuginfo~1.1.2~lp154.2.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apptainer", rpm:"apptainer~1.1.2~lp154.2.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apptainer-debuginfo", rpm:"apptainer-debuginfo~1.1.2~lp154.2.1", rls:"openSUSELeap15.4"))) {
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
