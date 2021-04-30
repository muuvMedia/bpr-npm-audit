#!/usr/bin/env node

const { spawnSync } = require("child_process");
const { request } = require("http");

const ORDERED_LEVELS = ["info", "low", "moderate", "high", "critical"];

const PROXY_TYPES = {
  local: "localhost",
  pipe: "host.docker.internal",
};

const npmSeverityToBitbucketSeverity = {
  info: "LOW",
  low: "LOW",
  moderate: "MEDIUM",
  high: "HIGH",
  critical: "CRITICAL",
};

const bitbucket = {
  branch: process.env.BITBUCKET_BRANCH,
  commit: process.env.BITBUCKET_COMMIT,
  owner: process.env.BITBUCKET_REPO_OWNER,
  slug: process.env.BITBUCKET_REPO_SLUG,
};

if (
  Object.keys(bitbucket).filter((key) => bitbucket[key]).length !==
  Object.keys(bitbucket).length
) {
  console.error("Not all Bitbucket environment variables were set.");
  process.exit(1);
}

const reportName = process.env.BPR_NAME || "Security: npm audit";
const reportId = process.env.BPR_ID || "npmaudit";
const proxyHost = PROXY_TYPES[process.env.BPR_PROXY || "local"];
const auditLevel = process.env.BPR_LEVEL || "high";
const majorVersionThreshold = process.env.VERSION_THRESHOLD || 1;
const includeNpmOutdated = process.env.INCLUDE_OUTDATED || false;

if (!ORDERED_LEVELS.includes(auditLevel)) {
  console.error("Unsupported audit level.");
  process.exit(1);
}
if (!proxyHost) {
  console.error("Unsupported proxy configuration.");
  process.exit(1);
}

const getOutdatedSeverity = ({ current, latest }) => {
  if (!current || !latest) {
    return 'NA';
  }
  const outBy = Number(latest.split(".")[0]) - Number(current.split(".")[0]);

  if (outBy < majorVersionThreshold) {
    return npmSeverityToBitbucketSeverity.low;
  }
  if (outBy > majorVersionThreshold) {
    return npmSeverityToBitbucketSeverity.high;
  }
  return npmSeverityToBitbucketSeverity.moderate;
};

const startTime = new Date().getTime();
const { stderr, stdout } = spawnSync("npm", ["audit", "--json"]);

if (stderr.toString()) {
  console.error(
    "Could not execute the `npm audit` command.",
    stderr.toString()
  );
  process.exit(1);
}
const audit = JSON.parse(stdout.toString());

const { stderr: outdatedError, stdout: outdatedJson } = spawnSync("npm", [
  "outdated",
  "--json",
]);

if (outdatedError.toString()) {
  console.error(
    "Could not execute the `npm outdated` command.",
    outdatedError.toString()
  );
  process.exit(1);
}
const outdatedPackages = JSON.parse(outdatedJson.toString());

const highestLevelIndex = ORDERED_LEVELS.reduce((value, level, index) => {
  return audit.metadata.vulnerabilities[level] ? index : value;
}, -1);

const push = (bitbucketUrl, data) =>
  new Promise((resolve, reject) => {
    const options = {
      host: proxyHost,
      port: 29418,
      path: bitbucketUrl,
      method: "PUT",
      headers: { "Content-Type": "application/json" },
    };
    const req = request(options, (response) => {
      let body = "";

      response.setEncoding("utf8");
      response.on("data", (chunk) => {
        body += chunk.toString();
      });
      response.on("end", () => {
        if (response.statusCode !== 200) {
          console.error(
            "Could not push report to Bitbucket.",
            response.statusCode,
            body
          );
          process.exit(1);
        } else {
          resolve();
        }
      });
    });

    req.write(JSON.stringify(data));
    req.end();
  });

const baseUrl = [
  "https://api.bitbucket.org/2.0/repositories/",
  bitbucket.owner,
  "/",
  bitbucket.slug,
  "/commit/",
  bitbucket.commit,
  "/reports/",
  reportId,
].join("");

const pushAllReports = async () => {
  await push(baseUrl, {
    title: reportName,
    details: "Results of npm audit & outdated.",
    report_type: "SECURITY",
    reporter: bitbucket.owner,
    result:
      highestLevelIndex <= ORDERED_LEVELS.indexOf(auditLevel)
        ? "PASSED"
        : "FAILED",
    data: [
      {
        title: "Duration (seconds)",
        type: "DURATION",
        value: Math.round((new Date().getTime() - startTime) / 1000),
      },
      {
        title: "Dependencies",
        type: "NUMBER",
        value:
          audit.metadata.dependencies.total === undefined
            ? audit.metadata.totalDependencies
            : audit.metadata.dependencies.total,
      },
      {
        title: "Outdated Packages",
        type: "NUMBER",
        value: Object.keys(outdatedPackages).length,
      },
      {
        title: "Safe to merge?",
        type: "BOOLEAN",
        value: highestLevelIndex <= ORDERED_LEVELS.indexOf(auditLevel),
      },
    ],
  });

  for (const [id, advisory] of Object.entries(audit.advisories)) {
    await push(`${baseUrl}/annotations/${reportId}-${id}`, {
      annotation_type: "VULNERABILITY",
      summary: `${advisory.module_name}: ${advisory.title}`,
      details: `${advisory.overview}\n\n${advisory.recommendation}`,
      link: advisory.url,
      severity: npmSeverityToBitbucketSeverity[advisory.severity],
    });
  }

	if (includeNpmOutdated){
		for (const [key, value] of Object.entries(outdatedPackages)) {
      const { current, wanted, latest, location } = value;

      await push(`${baseUrl}/annotations/${reportId}-${key}`, {
        annotation_type: "CODE_SMELL",
        summary: `${key}: is outdated`,
        details: `Current: ${current} 
      						Wanted: ${wanted} 
      						Latest: ${latest}
									Location: ${location}`,
        severity: getOutdatedSeverity({ current, latest }),
      });
    }
	}
    
};

pushAllReports().then(() => {
  console.log("Report successfully pushed to Bitbucket.");
  process.exit(0);
});
