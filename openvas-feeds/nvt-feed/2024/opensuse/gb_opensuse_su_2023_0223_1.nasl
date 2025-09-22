# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833710");
  script_version("2025-03-11T05:38:16+0000");
  script_cve_id("CVE-2023-31486");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-03-11 05:38:16 +0000 (Tue, 11 Mar 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-05-08 17:06:34 +0000 (Mon, 08 May 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 07:44:56 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for perl (openSUSE-SU-2023:0223-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSEBackportsSLE-15-SP5");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2023:0223-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/E3ZS64YN6IDP4X4L3RSPD77DZ3YJT32J");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'perl'
  package(s) announced via the openSUSE-SU-2023:0223-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for perl-HTTP-Tiny fixes the following issues:

     perl-HTTP-Tiny was updated to 0.086:

     see /usr/share/doc/packages/perl-HTTP-Tiny/Changes

     0.086     2023-06-22 10:06:37-04:00 America/New_York

  - Fix code to use `$ENV{PERL_HTTP_TINY_SSL_INSECURE_BY_DEFAULT}` as
           documented.

     0.084     2023-06-14 06:35:01-04:00 America/New_York

  - No changes from 0.083-TRIAL.

     0.083     2023-06-11 07:05:45-04:00 America/New_York (TRIAL RELEASE)

         [!!! SECURITY !!!]

  - Changes the `verify_SSL` default parameter from `0` to `1`. Fixes
           CVE-2023-31486 (boo#1211002)

  - `$ENV{PERL_HTTP_TINY_SSL_INSECURE_BY_DEFAULT}` can be used to
           restore the
           old default if required.

     0.081     2022-07-17 09:01:51-04:00 America/New_York (TRIAL RELEASE)

           [FIXED]

  - No longer deletes the 'headers' key from post_form arguments
     hashref. [DOCS]

  - Noted that request/response content are handled as raw bytes.

     0.079     2021-11-04 12:33:43-04:00 America/New_York (TRIAL RELEASE)

           [FIXED]

  - Fixed uninitialized value warnings on older Perls when the
     REQUEST_METHOD environment variable is set and CGI_HTTP_PROXY is not.

     0.077     2021-07-22 13:07:14-04:00 America/New_York (TRIAL RELEASE)

           [ADDED]

  - Added a `patch` helper method for the HTTP `PATCH` verb.

  - If the REQUEST_METHOD environment variable is set, then
     CGI_HTTP_PROXY replaces HTTP_PROXY.

           [FIXED]

  - Unsupported scheme errors early without giving an uninitialized
     value warning first.

  - Sends Content-Length: 0 on empty body PUT/POST.  This is not in
     the spec, but some servers require this.

  - Allows optional status line reason, as clarified in RFC 7230.

  - Ignore SIGPIPE on reads as well as writes, as IO::Socket::SSL says
     that SSL reads can also send writes as a side effect.

  - Check if a server has closed a connection before preserving it for
     reuse.

           [DOCS]

  - Clarified that exceptions/errors result in 599 status codes.

           [PREREQS]

  - Optional IO::Socket::IP prereq must be at least version 0.32 to be
     used. This ensures correct timeout support.

     0.076     2018-08-05 21:07:38-04:00 America/New_York

  - No changes from 0.075-TRIAL.

     0.075     2018-08-01 07:03:36-04:00 America/New_York (TRIAL RELEASE)

           [CHANGED] - The 'peer' option now also can take a code reference

     0.073    ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'perl' package(s) on openSUSE Backports SLE-15-SP5.");

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

if(release == "openSUSEBackportsSLE-15-SP5") {

  if(!isnull(res = isrpmvuln(pkg:"perl-HTTP-Tiny", rpm:"perl-HTTP-Tiny~0.086~bp155.3.3.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-HTTP-Tiny", rpm:"perl-HTTP-Tiny~0.086~bp155.3.3.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
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