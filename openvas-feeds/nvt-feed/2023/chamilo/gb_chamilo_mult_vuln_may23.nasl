# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:chamilo:chamilo_lms";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126364");
  script_version("2023-10-12T05:05:32+0000");
  script_tag(name:"last_modification", value:"2023-10-12 05:05:32 +0000 (Thu, 12 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-05-10 08:47:25 +0000 (Wed, 10 May 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-06-20 17:15:00 +0000 (Tue, 20 Jun 2023)");

  script_cve_id("CVE-2023-31799", "CVE-2023-31800", "CVE-2023-31801", "CVE-2023-31802",
                "CVE-2023-31803", "CVE-2023-31804", "CVE-2023-31805", "CVE-2023-31806",
                "CVE-2023-31807", "CVE-2023-34944", "CVE-2023-34958", "CVE-2023-34959",
                "CVE-2023-34961", "CVE-2023-34962");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Chamilo LMS 1.11.x <= 1.11.18 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_chamilo_http_detect.nasl");
  script_mandatory_keys("chamilo/detected");

  script_tag(name:"summary", value:"Chamilo LMS is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2023-31799: An administrator could edit system announcements and insert XSS attacks.

  - CVE-2023-31800: Teachers and students through student group could add XSS into a forum title.

  - CVE-2023-31801: XSS through links pointing at the skills wheel.

  - CVE-2023-31802: A user could add XSS to his/her own profile on the social network.

  - CVE-2023-31803: An administrator could edit resources sequencing and insert XSS attacks.

  - CVE-2023-31804: XSS attacks in course category edition, specifically targeting Chamilo
  administrators.

  - CVE-2023-31805: An administrator could edit links on the homepage and insert XSS attacks.

  - CVE-2023-31806: A User could add XSS into its personal notes.

  - CVE-2023-31807: An attacker is able to enumerate the internal network and execute arbitrary
  system commands via a crafted Phar file.

  - CVE-2023-34944: Cross-site scripting (XSS) through SVG.

  - CVE-2023-34958: Incorrect access control allows a student subscribed to a given course to
  download documents belonging to another student if they know the document's ID.

  - CVE-2023-34959: An issue allows attackers to execute a Server-Side Request Forgery (SSRF) and
  obtain information on the services running on the server via crafted requests in the social and
  links tools.

  - CVE-2023-34961: Cross-site scripting (XSS) vulnerability via the /feedback/comment field.

  - CVE-2023-34962: Incorrect access control allows a student to arbitrarily access and modify
  another student's personal notes.");

  script_tag(name:"affected", value:"Chamilo LMS version 1.11.x through 1.11.18.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://support.chamilo.org/projects/chamilo-18/wiki/Security_issues#Issue-99-2023-04-11-Low-impact-Low-risk-XSS-in-system-announcements");
  script_xref(name:"URL", value:"https://support.chamilo.org/projects/chamilo-18/wiki/Security_issues#Issue-102-2023-04-11-Low-impact-Moderate-risk-XSS-in-forum-titles");
  script_xref(name:"URL", value:"https://support.chamilo.org/projects/chamilo-18/wiki/Security_issues#Issue-97-2023-04-11-Low-impact-High-risk-XSS-in-skills-wheel");
  script_xref(name:"URL", value:"https://support.chamilo.org/projects/chamilo-18/wiki/Security_issues#Issue-104-2023-04-11-Moderate-impact-High-risk-XSS-in-personal-profile");
  script_xref(name:"URL", value:"https://support.chamilo.org/projects/chamilo-18/wiki/Security_issues#Issue-100-2023-04-11-Low-impact-Low-risk-XSS-in-resources-sequencing");
  script_xref(name:"URL", value:"https://support.chamilo.org/projects/chamilo-18/wiki/Security_issues#Issue-96-2023-04-06-Low-impact-Moderate-risk-XSS-in-course-categories");
  script_xref(name:"URL", value:"https://support.chamilo.org/projects/chamilo-18/wiki/Security_issues#Issue-98-2023-04-11-Low-impact-Low-risk-XSS-in-homepage-edition");
  script_xref(name:"URL", value:"https://support.chamilo.org/projects/chamilo-18/wiki/Security_issues#Issue-103-2023-04-11-Low-impact-Moderate-risk-XSS-in-My-progress-tab");
  script_xref(name:"URL", value:"https://support.chamilo.org/projects/chamilo-18/wiki/Security_issues#Issue-101-2023-04-11-Low-impact-Low-risk-XSS-in-personal-notes-and-teacher-notes");
  script_xref(name:"URL", value:"https://support.chamilo.org/projects/1/wiki/Security_issues#Issue-109-2023-04-15-Moderate-impact-Moderate-risk-IDOR-in-workstudent-publication");
  script_xref(name:"URL", value:"https://support.chamilo.org/projects/1/wiki/Security_issues#Issue-111-2023-04-20-Moderate-impact-Low-risk-Multiple-blind-SSRF-in-links-and-social-tools");
  script_xref(name:"URL", value:"https://support.chamilo.org/projects/1/wiki/Security_issues#Issue-105-2023-04-15-Low-impact-Moderate-risk-XSS-in-student-work-comments");
  script_xref(name:"URL", value:"https://support.chamilo.org/projects/1/wiki/Security_issues#Issue-106-2023-04-15-Moderate-impact-Moderate-risk-A-student-can-access-and-modify-another-students-personal-notes");
  script_xref(name:"URL", value:"https://support.chamilo.org/projects/chamilo-18/wiki/Security_issues#Issue-113-2023-05-31-Low-impact-Low-risk-XSS-through-SVG");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range_exclusive(version: version, test_version_lo: "1.11.0", test_version_up: "1.11.18")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "See advisory", install_path: location);
    security_message(port: port, data: report);
    exit(0);
}

exit(99);
