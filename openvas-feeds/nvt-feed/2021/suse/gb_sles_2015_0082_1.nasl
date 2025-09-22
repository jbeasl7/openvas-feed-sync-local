# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2015.0082.1");
  script_cve_id("CVE-2014-9356", "CVE-2014-9357", "CVE-2014-9358");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2024-02-02T14:37:48+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:48 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-12-11 20:30:20 +0000 (Wed, 11 Dec 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2015:0082-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2015:0082-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2015/suse-su-20150082-1/");
  script_xref(name:"URL", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=752555#5");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'docker' package(s) announced via the SUSE-SU-2015:0082-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This docker version upgrade fixes the following security and non security issues, and adds the also additional features:

- Updated to 1.4.1 (2014-12-15):
 * Runtime:
 - Fix issue with volumes-from and bind mounts not being honored after
 create (fixes bnc#913213)

- Added e2fsprogs as runtime dependency, this is required when the
 devicemapper driver is used. (bnc#913211).
- Fixed owner & group for docker.socket (thanks to Andrei Dziahel and
 [link moved to references])

- Updated to 1.4.0 (2014-12-11):
 * Notable Features since 1.3.0:
 - Set key=value labels to the daemon (displayed in `docker info`),
 applied with new `-label` daemon flag
 - Add support for `ENV` in Dockerfile of the form: `ENV name=value
 name2=value2...`
 - New Overlayfs Storage Driver
 - `docker info` now returns an `ID` and `Name` field
 - Filter events by event name, container, or image
 - `docker cp` now supports copying from container volumes
 - Fixed `docker tag`, so it honors `--force` when overriding a tag for
 existing image.
- Changes introduced by 1.3.3 (2014-12-11):
 * Security:
 - Fix path traversal vulnerability in processing of absolute symbolic
 links (CVE-2014-9356) - (bnc#909709)
 - Fix decompression of xz image archives, preventing privilege
 escalation (CVE-2014-9357) - (bnc#909710)
 - Validate image IDs (CVE-2014-9358) - (bnc#909712)
 * Runtime:
 - Fix an issue when image archives are being read slowly
 * Client:
 - Fix a regression related to stdin redirection
 - Fix a regression with `docker cp` when destination is the current
 directory");

  script_tag(name:"affected", value:"'docker' package(s) on SUSE Linux Enterprise Server 12.");

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

  if(!isnull(res = isrpmvuln(pkg:"docker", rpm:"docker~1.4.1~16.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-debuginfo", rpm:"docker-debuginfo~1.4.1~16.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-debugsource", rpm:"docker-debugsource~1.4.1~16.1", rls:"SLES12.0"))) {
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
